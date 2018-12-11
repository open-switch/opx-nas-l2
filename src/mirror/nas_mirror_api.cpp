/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mirror_api.cpp
 */



#include "dell-base-mirror.h"
#include "dell-base-common.h"
#include "nas_mirror_api.h"

#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_api_key.h"
#include "cps_api_object_key.h"
#include "cps_api_object_tools.h"
#include "cps_class_map.h"
#include "event_log.h"
#include "hal_if_mapping.h"
#include "std_bit_masks.h"
#include "nas_base_utils.h"
#include "std_mutex_lock.h"
#include "nas_ndi_obj_id_table.h"

#include <algorithm>
#include <utility>
#include <unordered_set>


/*
 * @TODO Max mirroring session info to be retrieved from SAI
 */
#define MAX_MIRROR_SESSION 512

// Mirror Entry table
static auto  nas_mirror_table = new nas_mirror_table_t;

// Mirror IDs Map
static nas::id_generator_t nas_mirror_ids(MAX_MIRROR_SESSION);

static std_mutex_lock_create_static_init_fast(nas_mirror_mutex);
static auto dst_intf_set = new std::unordered_set<hal_ifindex_t> ;

static inline unsigned int nas_mirror_get_next_id(){
    return (unsigned int)nas_mirror_ids.alloc_id();
}


static inline void nas_mirror_release_id(unsigned int id){
    nas_mirror_ids.release_id((nas_obj_id_t)id);
}


static bool nas_mirror_intf_to_port(hal_ifindex_t ifindex,interface_ctrl_t *intf_ctrl){
    memset(intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl->q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl->if_index = ifindex;

    if (dn_hal_get_interface_info(intf_ctrl) != STD_ERR_OK) {
        NAS_MIRROR_LOG(ERR,"Interface %d has NO slot %d, port %d",
                   intf_ctrl->if_index, intf_ctrl->npu_id, intf_ctrl->port_id);
        return false;
    }

    return true;
}


static bool nas_mirror_intf_to_ndi_src_port(hal_ifindex_t ifindex, BASE_CMN_TRAFFIC_PATH_t dir,
                                              ndi_mirror_src_port_t *port){
    interface_ctrl_t intf_ctrl;
    if(!nas_mirror_intf_to_port(ifindex,&intf_ctrl)){
        return false;
    }
    port->src_port.npu_port = intf_ctrl.port_id;
    port->src_port.npu_id = intf_ctrl.npu_id;
    port->direction = dir;

    return true;
}


bool nas_mirror_entry::add_src_intf(hal_ifindex_t ifindex ,BASE_CMN_TRAFFIC_PATH_t dir){
    auto it = nas_mirror_src_intf.find(ifindex);
    if(it == nas_mirror_src_intf.end()){
        nas_mirror_src_intf.insert(nas_mirror_src_intf_pair(ifindex,dir));
        return true;
    }else if(it->second != dir){
        nas_mirror_src_intf[ifindex]=dir;
        return true;
    }
    return false;
}

static bool get_src_intf_attr(cps_api_object_t obj,
                              nas_mirror_src_intf_map_t & intf_map,
                              const cps_api_object_it_t & it,
                              bool update,
                              hal_ifindex_t stored_dst_intf)
{
    hal_ifindex_t dst_intf;
    cps_api_object_attr_t dst_intf_attr;
    cps_api_object_attr_t dst_lag_attr;

    /*
     * If this is an update, retrieve the stored destination interface.
     * If not, verify that the user has specified a destination interface,
     * and extract it from the CPS object.  If no destination interface has been
     * specified, return error.
     */
    if (update) {
        dst_intf = stored_dst_intf;
    } else {
        dst_intf_attr = cps_api_object_attr_get(obj, BASE_MIRROR_ENTRY_DST_INTF);
        if (dst_intf_attr) {
            dst_intf = cps_api_object_attr_data_u32(dst_intf_attr);
        } else {
            dst_lag_attr = cps_api_object_attr_get(obj,
                                                   BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA);
            if (dst_lag_attr) {
                dst_intf = cps_api_object_attr_data_u32(dst_lag_attr);
            }
        }

        /*
         * Sanity
         */
        if ((dst_intf_attr == nullptr) && (dst_lag_attr == nullptr)) {
            EV_LOGGING(NAS_L2, ERR, "MIRROR",
                       "No destination interface for a new mirror session");
            return false;
        }
    }

    cps_api_object_it_t it_lvl_1 = it;
    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF,0, BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        ids[1] = cps_api_object_attr_id (it_lvl_1.attr);
        ids[2]=BASE_MIRROR_ENTRY_INTF_SRC;
        cps_api_object_attr_t src_intf = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
        cps_api_object_attr_t direction = cps_api_object_e_get(obj,ids,ids_len);

        if(src_intf == NULL){
            NAS_MIRROR_LOG(ERR,"Source Interface Index not passed for creating/updating a session");
            return false;
        }

        if(direction == NULL){
           NAS_MIRROR_LOG(ERR,"Mirroring Direction not passed for creating/updating a session");
           return false;
        }

        hal_ifindex_t ifindex = cps_api_object_attr_data_u32(src_intf);

        if (ifindex == dst_intf) {
            EV_LOGGING(NAS_L2,ERR,"MIRROR","Source and Destination interface for "
                       "mirror session can't be same");
            return false;
        }

        BASE_CMN_TRAFFIC_PATH_t dir = (BASE_CMN_TRAFFIC_PATH_t)cps_api_object_attr_data_u32(direction);
        if(intf_map.find(ifindex) == intf_map.end()){
            intf_map[ifindex] = dir;
        }
    }

    return true;
}


static t_std_error nas_mirror_update_src_port(nas_mirror_entry * entry,hal_ifindex_t ifindex,
                  BASE_CMN_TRAFFIC_PATH_t current_dir,BASE_CMN_TRAFFIC_PATH_t old_dir){

    ndi_mirror_src_port_t port;
    t_std_error rc = STD_ERR(MIRROR,FAIL,0);
    if(!nas_mirror_intf_to_ndi_src_port(ifindex,current_dir,&port)) return rc;

    /*
     * Update the direction for source Mirror Port
     * if old dir ingress and new dir egress, disable ingress and enable egress
     * if old dir egress and new dir ingress, disable egress and enable ingress
     * if old dir egress/ingress and new dir ingress_egress, enable egress and ingress
     * if old dir ingress_egress and new dir ingress/egress, disable ingress/egress
     */
    if((port.direction == BASE_CMN_TRAFFIC_PATH_INGRESS && old_dir == BASE_CMN_TRAFFIC_PATH_EGRESS) ||
       (port.direction == BASE_CMN_TRAFFIC_PATH_EGRESS && old_dir == BASE_CMN_TRAFFIC_PATH_INGRESS)){
        BASE_CMN_TRAFFIC_PATH_t new_dir = port.direction;
        port.direction = old_dir;
        if((rc = ndi_mirror_update_direction(entry->get_ndi_entry(),port, false))!=STD_ERR_OK) return rc;
        port.direction = new_dir;
        if((rc =ndi_mirror_update_direction(entry->get_ndi_entry(),port, true))!=STD_ERR_OK) return rc;

    }else if(port.direction== BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS){
        if(old_dir == BASE_CMN_TRAFFIC_PATH_INGRESS){
            port.direction = BASE_CMN_TRAFFIC_PATH_EGRESS;
        }else{
            port.direction = BASE_CMN_TRAFFIC_PATH_INGRESS;
        }
        if((rc = ndi_mirror_update_direction(entry->get_ndi_entry(),port, true))!=STD_ERR_OK){
            return rc;
        }
    }else if(old_dir == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS){
        if(port.direction == BASE_CMN_TRAFFIC_PATH_INGRESS){
            port.direction = BASE_CMN_TRAFFIC_PATH_EGRESS;
        }else{
            port.direction = BASE_CMN_TRAFFIC_PATH_INGRESS;
        }
        if((rc = ndi_mirror_update_direction(entry->get_ndi_entry(),port, false))!=STD_ERR_OK){
            return rc;
        }
    }
    return STD_ERR_OK;
}


t_std_error nas_mirror_add_del_src_port(ndi_mirror_entry_t * entry,hal_ifindex_t ifindex,
                                    BASE_CMN_TRAFFIC_PATH_t dir, bool enable){
    ndi_mirror_src_port_t port;
    t_std_error rc;
    if(!nas_mirror_intf_to_ndi_src_port(ifindex,dir,&port)) return STD_ERR(MIRROR,PARAM,0);

    if(port.direction == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS){
        port.direction = BASE_CMN_TRAFFIC_PATH_INGRESS;
        if((rc = ndi_mirror_update_direction(entry,port, enable))!=STD_ERR_OK){
            return rc;
        }
        port.direction = BASE_CMN_TRAFFIC_PATH_EGRESS;
        if((rc = ndi_mirror_update_direction(entry,port, enable))!=STD_ERR_OK){
            port.direction = BASE_CMN_TRAFFIC_PATH_INGRESS;
            ndi_mirror_update_direction(entry,port, !(enable));
            return rc;
        }
    }else{
        if((rc = ndi_mirror_update_direction(entry,port, enable))!=STD_ERR_OK){
            return rc;
        }
    }
    return STD_ERR_OK;
}


bool nas_mirror_entry::remove_src_intf(){
    for(auto it = nas_mirror_src_intf.begin() ; it != nas_mirror_src_intf.end() ; ++it){
        if(nas_mirror_add_del_src_port(&ndi_mirror_entry,it->first,it->second,false) != STD_ERR_OK) return false;
    }
    return true;
}


t_std_error nas_mirror_entry::update_src_intf_map(nas_mirror_src_intf_map_t & intf_map){

    /*
     * Check if existing source interface exist in the new list, if not then delete
     * it from the source interface map and from NPU
     *
     * Check if new source interface is in the source interface map, if not then add it
     * and update the NPU
     *
     * If an entry is there but its direction is changed then update the source mirror
     * interface direction
     */
    t_std_error rc;
    for(auto it = nas_mirror_src_intf.begin() ; it != nas_mirror_src_intf.end() ;){
        auto intf_it = intf_map.find(it->first);
        if(intf_it == intf_map.end()){
            if((rc = nas_mirror_add_del_src_port(&ndi_mirror_entry,it->first,
                     it->second, false))!=STD_ERR_OK) {
                return rc;
            }
            nas_mirror_src_intf.erase(it++);
        }else{
            ++it;
        }
    }

    for(auto it = intf_map.begin() ; it != intf_map.end() ; ++it){
        auto intf_it = nas_mirror_src_intf.find(it->first);
        if(intf_it == nas_mirror_src_intf.end()){
            if((rc = nas_mirror_add_del_src_port(&ndi_mirror_entry,it->first,
                     it->second,true)) != STD_ERR_OK){
                return rc;
            }
            nas_mirror_src_intf[it->first]=it->second;
        }else if(intf_it->second != it->second){
            if((rc = nas_mirror_update_src_port(&(*this),it->first,
                     it->second,intf_it->second)) != STD_ERR_OK) return rc;
            nas_mirror_src_intf[intf_it->first]=it->second;
        }
    }
    return STD_ERR_OK;
}



static inline bool nas_mirror_validate_attr(nas::attr_set_t &attrs){

    if(!((attrs.contains(BASE_MIRROR_ENTRY_DST_INTF) ||
          attrs.contains(BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA)) &&
          attrs.contains(BASE_MIRROR_ENTRY_TYPE))){
        NAS_MIRROR_LOG(ERR,"Missing Necessary Parameters for creating a Mirroring Session");
        return false;
    }
    return true;
}


static inline bool nas_mirror_validate_erspan_attr(nas::attr_set_t &attrs){

    if(!(attrs.contains(BASE_MIRROR_ENTRY_SOURCE_IP) && attrs.contains(BASE_MIRROR_ENTRY_DESTINATION_IP) &&
        attrs.contains(BASE_MIRROR_ENTRY_SOURCE_MAC) && attrs.contains(BASE_MIRROR_ENTRY_DEST_MAC))) {
        NAS_MIRROR_LOG(ERR,"Missing Necessary Parameters for creating a ERSPAN Mirroring Session");
        return false;
    }
    return true;
}


static bool nas_mirror_update_attrs(nas_mirror_entry *entry, nas::attr_set_t & attrs){
    for(auto attr_id: attrs){
        if(attr_id == BASE_MIRROR_ENTRY_INTF) continue;
        if(ndi_mirror_update_session(entry->get_ndi_entry(),(BASE_MIRROR_ENTRY_t)attr_id) != STD_ERR_OK){
            return false;
        }
    }
    return true;
}


static bool nas_mirror_fill_rspan_attr(cps_api_object_t obj, nas_mirror_entry * entry, bool update){

    nas::attr_set_t attrs;

    cps_api_object_attr_t vlan_attr;
    cps_api_attr_id_t vlan_attr_id = BASE_MIRROR_ENTRY_VLAN;

    vlan_attr = cps_api_object_e_get (obj, &vlan_attr_id, 1);
    if(!update && vlan_attr == NULL){
        NAS_MIRROR_LOG(ERR,"No VLAN Id Passed for creating rspan mirror session");
        return false;
    }

    if(vlan_attr != NULL){
        attrs.add(BASE_MIRROR_ENTRY_VLAN);
        entry->set_vlan(cps_api_object_attr_data_u32(vlan_attr));

        if(update){
           return nas_mirror_update_attrs(entry,attrs);
        }
    }

    return true;
}


static bool nas_mirror_fill_erspan_attr(cps_api_object_t obj, nas_mirror_entry *entry, bool update){

    nas::attr_set_t attrs;
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {

        case BASE_MIRROR_ENTRY_ERSPAN_VLAN_ID:
            if(attrs.contains(BASE_MIRROR_ENTRY_ERSPAN_VLAN_ID)){
                NAS_MIRROR_LOG(ERR,"Multiple VLAN Ids passed for creating ERSPAN Mirroring session");
                   return false;
            }
            entry->set_vlan(cps_api_object_attr_data_u32(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_ERSPAN_VLAN_ID);
            break;

        case BASE_MIRROR_ENTRY_DESTINATION_IP:
            if( attrs.contains(BASE_MIRROR_ENTRY_DESTINATION_IP)){
                NAS_MIRROR_LOG(ERR,"Multiple Dst IP Address passed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_dst_ip(cps_api_object_attr_data_u32(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_DESTINATION_IP);
            break;

        case BASE_MIRROR_ENTRY_SOURCE_IP:
            if( attrs.contains(BASE_MIRROR_ENTRY_SOURCE_IP)){
                NAS_MIRROR_LOG(ERR,"Multiple Source IP Address passed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_src_ip(cps_api_object_attr_data_u32(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_SOURCE_IP);
            break;


        case BASE_MIRROR_ENTRY_DEST_MAC:
            if( attrs.contains(BASE_MIRROR_ENTRY_DEST_MAC)){
                NAS_MIRROR_LOG(ERR,"Multiple Dst MAC Address passed for creating ERSPAN Mirroring session");
                return false;
            }

            entry->set_dst_mac(cps_api_object_attr_data_bin(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_DEST_MAC);
            break;

        case BASE_MIRROR_ENTRY_SOURCE_MAC:
            if( attrs.contains(BASE_MIRROR_ENTRY_SOURCE_MAC)){
                NAS_MIRROR_LOG(ERR,"Multiple Source MAC Address passed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_src_mac(cps_api_object_attr_data_bin(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_SOURCE_MAC);
            break;

        case BASE_MIRROR_ENTRY_TTL:
            if( attrs.contains(BASE_MIRROR_ENTRY_TTL)){
                NAS_MIRROR_LOG(ERR,"Multiple TTL value passed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_ttl(cps_api_object_attr_data_uint(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_TTL);
            break;

        case BASE_MIRROR_ENTRY_DSCP:
            if( attrs.contains(BASE_MIRROR_ENTRY_DSCP)){
                NAS_MIRROR_LOG(ERR,"Multiple DSCP value passed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_dscp(cps_api_object_attr_data_uint(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_DSCP);
            break;

        case BASE_MIRROR_ENTRY_GRE_PROTOCOL_TYPE:
            if( attrs.contains(BASE_MIRROR_ENTRY_GRE_PROTOCOL_TYPE)){
                NAS_MIRROR_LOG(ERR,"Multiple GRE protocol valuepassed for creating ERSPAN Mirroring session");
                return false;
            }
            entry->set_gre_prot_type(cps_api_object_attr_data_u16(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_GRE_PROTOCOL_TYPE);
            break;


        }
    }

    if(update){
        return nas_mirror_update_attrs(entry,attrs);
    }
    return nas_mirror_validate_erspan_attr(attrs);
}


static bool nas_mirror_fill_entry(cps_api_object_t obj,nas_mirror_entry *entry
                                 ,nas_mirror_src_intf_map_t  & new_intf_map,bool update){

    nas::attr_set_t attrs;
    cps_api_object_it_t it;
    hal_ifindex_t dst_intf;

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {

        case BASE_MIRROR_ENTRY_DST_INTF :
            if(attrs.contains(BASE_MIRROR_ENTRY_DST_INTF) ||
               attrs.contains(BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA)){
                NAS_MIRROR_LOG(ERR,"Multiple Destination Interface Index passed "
                        "for creating/updating Mirroring session");
                return false;
            }

            entry->set_dst_intf(cps_api_object_attr_data_u32(it.attr));
            interface_ctrl_t intf_ctrl;
            if(!nas_mirror_intf_to_port(entry->get_dst_intf(),&intf_ctrl)){
                return false;
            }

            entry->set_dst_port(intf_ctrl.npu_id,intf_ctrl.port_id);
            attrs.add(BASE_MIRROR_ENTRY_DST_INTF);
            break;

        case BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA :
            if(attrs.contains(BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA) ||
               attrs.contains(BASE_MIRROR_ENTRY_DST_INTF)){
                NAS_MIRROR_LOG(ERR,"Multiple Destination Lag opaque data "
                               "passed for creating/updating Mirroring session");
                return false;
            }

            {
                nas::ndi_obj_id_table_t lag_opaque_data_table;
                cps_api_attr_id_t  attr_id_list[] = {BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA};
                if(!nas::ndi_obj_id_table_cps_unserialize (lag_opaque_data_table, obj,attr_id_list,
                                                           sizeof(attr_id_list)/
                                                           sizeof(attr_id_list[0]))){
                    NAS_MIRROR_LOG(ERR,"Failed to unserialize lag opaque data");
                    return false;
                }

                auto lag_opaue_it = lag_opaque_data_table.begin();
                if(lag_opaue_it == lag_opaque_data_table.end()){
                    NAS_MIRROR_LOG(ERR,"No lag opaque data passed");
                    return false;
                }

                entry->set_ndi_lag_id(lag_opaue_it->first,lag_opaue_it->second);
            }
            attrs.add(BASE_MIRROR_ENTRY_LAG_OPAQUE_DATA);
            break;

        case BASE_MIRROR_ENTRY_INTF:
            attrs.add(BASE_MIRROR_ENTRY_INTF);

            if(update && (!cps_api_object_attr_len(it.attr))){
                 continue;
            }

            dst_intf = entry->get_dst_intf();
            if (!get_src_intf_attr(obj, new_intf_map, it, update, dst_intf))
                return false;
            break;

        case BASE_MIRROR_ENTRY_FLOW_ENABLED :
            entry->set_flow(cps_api_object_attr_data_u32(it.attr));
            break;

        case BASE_MIRROR_ENTRY_TYPE:
            if(attrs.contains(BASE_MIRROR_ENTRY_TYPE)){
                NAS_MIRROR_LOG(ERR,"Multiple Mirror types passed "
                        "for creating Mirroring session");
                return false;
            }
            entry->set_mode((BASE_MIRROR_MODE_t)cps_api_object_attr_data_u32(it.attr));
            attrs.add(BASE_MIRROR_ENTRY_TYPE);
            break;
        }
    }

    if(update){
        if(!nas_mirror_update_attrs(entry,attrs)) return false;
        if(attrs.contains(BASE_MIRROR_ENTRY_INTF)){
            if(new_intf_map.size()){
                t_std_error rc;
                if(( rc = entry->update_src_intf_map(new_intf_map)) != STD_ERR_OK){
                    cps_api_object_set_return_code(obj,rc);
                    return false;
                }
            }else{
                if(!entry->remove_src_intf()){
                    return false;
                }
            }
        }
    }
    else{
        if(!nas_mirror_validate_attr(attrs)) return false;
    }

    if(entry->get_mode() == BASE_MIRROR_MODE_RSPAN ){
        if(!nas_mirror_fill_rspan_attr(obj,entry,update)){
            return false;
        }
    }

    if(entry->get_mode() == BASE_MIRROR_MODE_ERSPAN){
       if(!nas_mirror_fill_erspan_attr(obj,entry,update)){
           return false;
       }
    }

    return true;
}


t_std_error nas_mirror_create_session(cps_api_object_t obj) {

    nas_mirror_entry entry;
    nas_mirror_src_intf_map_t intf_map;
    if(!nas_mirror_fill_entry(obj,&entry,intf_map,false)){
        return STD_ERR(MIRROR,CFG,0);
    }

    std_mutex_simple_lock_guard lock(&nas_mirror_mutex);

    bool invalid = false;
    for(auto it : intf_map){
        auto dst_it = dst_intf_set->find(it.first);
        if(dst_it != dst_intf_set->end() ){
            invalid = true;
            break;
        }
    }

    if(invalid){
        EV_LOGGING(NAS_L2,ERR,"MIRROR","Source interface cannot be part of other mirror "
                "session as Destination interface ");
        return STD_ERR(MIRROR,CFG,0);
    }


    if(ndi_mirror_create_session(entry.get_ndi_entry()) != STD_ERR_OK){
        return STD_ERR(MIRROR,FAIL,0);
    }

    t_std_error rc;
    if(( rc = entry.update_src_intf_map(intf_map)) != STD_ERR_OK ){
        cps_api_object_set_return_code(obj,rc);
        if(!entry.remove_src_intf()){
            NAS_MIRROR_LOG(ERR,"Failed to remove source ports while create failure "
                           "for Mirror Session");
            return rc;
        }
        NAS_MIRROR_LOG(ERR,"Failed to Enable Mirroring on Source Ports");
        ndi_mirror_delete_session(entry.get_ndi_entry());
        return rc;
    }

    dst_intf_set->insert(entry.get_dst_intf());


    nas_mirror_id_t id = nas_mirror_get_next_id();
    entry.set_id(id);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                &id,sizeof(id));
    nas::ndi_obj_id_table_t mirror_opaque_data_table;
    mirror_opaque_data_table[entry.get_npu_id()] = entry.get_ndi_id();
    cps_api_attr_id_t  attr_id_list[] = {BASE_MIRROR_ENTRY_OPAQUE_DATA};
    nas::ndi_obj_id_table_cps_serialize (mirror_opaque_data_table, obj, attr_id_list,
                                                sizeof(attr_id_list)/sizeof(attr_id_list[0]));
    NAS_MIRROR_LOG(DEBUG,"Created New Mirror Session with id %d",entry.get_id());
    nas_mirror_table->insert(nas_mirror_table_pair(entry.get_id(),std::move(entry)));

    return STD_ERR_OK;
}


t_std_error nas_mirror_delete_session(cps_api_object_t obj,nas_mirror_id_t id) {

    std_mutex_simple_lock_guard lock(&nas_mirror_mutex);
    nas_mirror_table_it it = nas_mirror_table->find(id);

    if(it == nas_mirror_table->end()){
        NAS_MIRROR_LOG(ERR,"No Mirror oid %d exist",(int)id);
        return STD_ERR(MIRROR,NEXIST,0);
    }

    nas_mirror_entry & entry = it->second;
    if(!entry.remove_src_intf()){
        NAS_MIRROR_LOG(ERR,"Failed to remove source ports for Mirror Session %d",
                entry.get_id());
        return STD_ERR(MIRROR,FAIL,0);
    }

    if(ndi_mirror_delete_session(entry.get_ndi_entry()) != STD_ERR_OK){
        return STD_ERR(MIRROR,FAIL,0);
    }

    NAS_MIRROR_LOG(DEBUG,"Deleted Mirror Session Id %d",entry.get_id());
    dst_intf_set->erase(entry.get_dst_intf());
    nas_mirror_release_id(entry.get_id());
    nas_mirror_table->erase(it);
    return STD_ERR_OK;
}


t_std_error nas_mirror_set_session(cps_api_object_t obj,nas_mirror_id_t id){

    nas_mirror_table_it it = nas_mirror_table->find(id);
    NAS_MIRROR_LOG(DEBUG,"updating mirror session %d",(int)id);
    if(it == nas_mirror_table->end()){
        NAS_MIRROR_LOG(ERR,"No Mirror id %d exist for updating mirror session",(int)id);
        return STD_ERR(MIRROR,NEXIST,0);
    }

    nas_mirror_entry & entry = it->second;
    nas_mirror_src_intf_map_t intf_map;
    std_mutex_simple_lock_guard lock(&nas_mirror_mutex);
    nas_mirror_entry orig_entry(entry);
    if(!(nas_mirror_fill_entry(obj,&entry,intf_map,true))){
        const t_std_error *rc = cps_api_object_return_code(obj);
        entry = std::move(orig_entry);
        if(rc != nullptr){
             return *rc;
        }
        return STD_ERR(MIRROR,FAIL,0);
    }
    return STD_ERR_OK;
}


static void nas_mirror_fill_object(cps_api_object_t obj, nas_mirror_table_it it){

    nas_mirror_entry & entry = it->second;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);
    nas_mirror_id_t id = entry.get_id();
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                         &id,sizeof(id));
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_ID,id);

    nas::ndi_obj_id_table_t mirror_opaque_data_table;
    mirror_opaque_data_table[entry.get_npu_id()] = entry.get_ndi_id();
    cps_api_attr_id_t  attr_id_list[] = {BASE_MIRROR_ENTRY_OPAQUE_DATA};
    nas::ndi_obj_id_table_cps_serialize (mirror_opaque_data_table, obj, attr_id_list,
                                         sizeof(attr_id_list)/sizeof(attr_id_list[0]));


    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,entry.get_dst_intf());
    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF,0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    for(auto src_it = entry.get_src_intf_map()->begin() ; src_it != entry.get_src_intf_map()->end() ; ++src_it){
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_it->first),sizeof(src_it->first));
        ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_it->second),sizeof(src_it->second));
        ids[2]=BASE_MIRROR_ENTRY_INTF_SRC;
        ++ids[1];
    }

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_FLOW_ENABLED,entry.get_flow());
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TYPE,entry.get_mode());

    if(entry.get_mode() == BASE_MIRROR_MODE_RSPAN){
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_VLAN,entry.get_vlan_id());
    }

    if(entry.get_mode() == BASE_MIRROR_MODE_ERSPAN){
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_SOURCE_IP,entry.get_src_ip()->u.v4_addr);
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DESTINATION_IP,entry.get_dst_ip()->u.v4_addr);
        cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_SOURCE_MAC,(void *)entry.get_src_mac(),sizeof(hal_mac_addr_t));
        cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_DEST_MAC,(void *)entry.get_dst_mac(),sizeof(hal_mac_addr_t));
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_ERSPAN_VLAN_ID,entry.get_vlan_id());
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TTL,entry.get_ttl());
        cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DSCP,entry.get_dscp());
        cps_api_object_attr_add_u16(obj,BASE_MIRROR_ENTRY_GRE_PROTOCOL_TYPE,entry.get_gre_prot_type());
    }
}


t_std_error nas_mirror_get_all_info(cps_api_object_list_t list){

    std_mutex_simple_lock_guard lock(&nas_mirror_mutex);
    auto it = nas_mirror_table->begin();

    for ( ; it != nas_mirror_table->end() ; ++it){
        cps_api_object_t obj=cps_api_object_create();

        if (obj==NULL) {
            NAS_MIRROR_LOG(ERR,"Failed to create a new object");
            return STD_ERR(MIRROR,NOMEM,0);
        }

        if (!cps_api_object_list_append(list,obj)) {
            cps_api_object_delete(obj);
            NAS_MIRROR_LOG(ERR,"Failed to append object to object list");
            return STD_ERR(MIRROR,FAIL,0);
        }
        nas_mirror_fill_object(obj,it);
    }

    return STD_ERR_OK;
}


t_std_error nas_mirror_get_session_info(cps_api_object_list_t list, nas_mirror_id_t id){

    std_mutex_simple_lock_guard lock(&nas_mirror_mutex);

    auto it = nas_mirror_table->find(id);

    if(it == nas_mirror_table->end()){
        NAS_MIRROR_LOG(ERR,"No NAS Mirror session with Id %d exist",(int)id);
        return STD_ERR(MIRROR,NEXIST,0);
    }

    cps_api_object_t obj=cps_api_object_create();

    if (obj==NULL) {
        NAS_MIRROR_LOG(ERR,"Failed to create a new object");
        return STD_ERR(MIRROR,NOMEM,0);
    }

    if (!cps_api_object_list_append(list,obj)) {
        cps_api_object_delete(obj);
        NAS_MIRROR_LOG(ERR,"Failed to append object to object list");
        return STD_ERR(MIRROR,FAIL,0);
    }

    nas_mirror_fill_object(obj,it);
    return STD_ERR_OK;
}


