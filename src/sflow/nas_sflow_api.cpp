/*
 * Copyright (c) 2016 Dell Inc.
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
 * filename: nas_sflow_api.cpp
 */


#include "nas_sflow_api.h"
#include "dell-base-sflow.h"
#include "cps_api_events.h"
#include "hal_if_mapping.h"
#include "nas_base_utils.h"
#include "std_mutex_lock.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

#include <mutex>
#include <utility>
#include <stdlib.h>

/*@TODO update this value and get it from SAI when SAI SFLOW is available */
#define MAX_SFLOW_SESSION 512

static std_mutex_lock_create_static_init_fast(nas_sflow_mutex);

//NAS sFlow id generator
static nas::id_generator_t nas_sflow_ids(MAX_SFLOW_SESSION);

//NAS sFlow table which stores all session information
static auto nas_sflow_table = new nas_sflow_map_t;


static inline unsigned int nas_sflow_get_next_index(){
   return nas_sflow_ids.alloc_id();
}


static inline void nas_sflow_remove_index(unsigned int ix){
    nas_sflow_ids.release_id(ix);
}


static bool nas_validate_sflow_entry(nas_sflow_entry_t *entry){

    if(!entry->attr_set.contains(BASE_SFLOW_ENTRY_DIRECTION)){
        NAS_SFLOW_LOG(ERR,"Missing SFLOW_ENTRY_TABLE_DIRECTION Parameter"
                                           "for creating sFlow session");
        return false;
    }

    if(!entry->attr_set.contains(BASE_SFLOW_ENTRY_SAMPLING_RATE)){
        NAS_SFLOW_LOG(ERR,"Missing SFLOW_ENTRY_TABLE_SAMPLING_RATE Parameter"
                                    "for creating sFlow session");
        return false;
    }

    if(!entry->attr_set.contains(BASE_SFLOW_ENTRY_IFINDEX)){
        NAS_SFLOW_LOG(ERR,"Missing ifindex/ifname Parameter for creating sFlow session");
        return false;
    }
    return true;
}


static bool nas_sflow_update_session_attr(ndi_sflow_entry_t *entry, int attr_id, uint32_t attr_val){

    if(attr_id == BASE_SFLOW_ENTRY_DIRECTION){
        if(entry->sflow_direction == attr_val) {
            return true;
        }
        if (attr_val != BASE_CMN_TRAFFIC_PATH_INGRESS &&
            attr_val != BASE_CMN_TRAFFIC_PATH_EGRESS &&
            attr_val != BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS) {
            return false;
        }
        if (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS) {
            if (attr_val == BASE_CMN_TRAFFIC_PATH_INGRESS) {
                if (ndi_sflow_update_direction(entry, BASE_CMN_TRAFFIC_PATH_EGRESS, false)
                    != STD_ERR_OK) {
                    return false;
                }
            } else if (attr_val == BASE_CMN_TRAFFIC_PATH_EGRESS) {
                if (ndi_sflow_update_direction(entry, BASE_CMN_TRAFFIC_PATH_INGRESS, false)
                    != STD_ERR_OK) {
                    return false;
                }
            }
        } else if (attr_val == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS) {
            if (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS) {
                if (ndi_sflow_update_direction(entry, BASE_CMN_TRAFFIC_PATH_EGRESS, true)
                    != STD_ERR_OK) {
                    return false;
                }
            } else if (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_EGRESS) {
                if (ndi_sflow_update_direction(entry, BASE_CMN_TRAFFIC_PATH_INGRESS, true)
                    != STD_ERR_OK) {
                    return false;
                }
            }
        } else {
            if (ndi_sflow_update_direction(entry, entry->sflow_direction, false)
                != STD_ERR_OK) {
                return false;
            }
            if (ndi_sflow_update_direction(entry, (BASE_CMN_TRAFFIC_PATH_t)attr_val, true)
                != STD_ERR_OK) {
                if (ndi_sflow_update_direction(entry, entry->sflow_direction, true) != STD_ERR_OK) {
                    return false;
                }
                return false;
            }
        }
    }
    else if(attr_id == BASE_SFLOW_ENTRY_SAMPLING_RATE){
        if(ndi_sflow_update_session(entry,BASE_SFLOW_ENTRY_SAMPLING_RATE)!=STD_ERR_OK ){
            return false;
        }
    }
    return true;
}

static bool nas_sflow_update_direction(ndi_sflow_entry_t * entry, bool enable){
    if (entry->sflow_direction != BASE_CMN_TRAFFIC_PATH_INGRESS &&
        entry->sflow_direction != BASE_CMN_TRAFFIC_PATH_EGRESS &&
        entry->sflow_direction != BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS) {
        return false;
    }

    if((entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS) ||
       (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS)){
        if(ndi_sflow_update_direction(entry,BASE_CMN_TRAFFIC_PATH_INGRESS, enable)!=STD_ERR_OK ){
            return false;
        }
    }

    if((entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_EGRESS) ||
       (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS)){
        if(ndi_sflow_update_direction(entry,BASE_CMN_TRAFFIC_PATH_EGRESS, enable)!=STD_ERR_OK ){
            if (entry->sflow_direction == BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS){
                if(ndi_sflow_update_direction(entry,BASE_CMN_TRAFFIC_PATH_INGRESS, !enable)
                                             !=STD_ERR_OK ){
                    return false;
                }
            }
            return false;
        }
    }
    return true;
}


static bool nas_sflow_fill_session_info(cps_api_object_t obj,nas_sflow_entry_t *entry){

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);

        switch (id) {

        case BASE_SFLOW_ENTRY_IFINDEX :
            if(entry->attr_set.contains(BASE_SFLOW_ENTRY_IFINDEX)){
                NAS_SFLOW_LOG(ERR,"Multiple Interface Index passed "
                        "for creating sFlow session");
                return false;
            }
            entry->ifindex = cps_api_object_attr_data_u32(it.attr);
            entry->attr_set.add(BASE_SFLOW_ENTRY_IFINDEX);
            break;

        case BASE_SFLOW_ENTRY_IF_INDEX_IFINDEX:
            if(entry->attr_set.contains(BASE_SFLOW_ENTRY_IFINDEX)){
                NAS_SFLOW_LOG(ERR,"Multiple Interface Index passed "
                        "for creating sFlow session");
                return false;
            }
            entry->ifindex = cps_api_object_attr_data_u32(it.attr);
            entry->attr_set.add(BASE_SFLOW_ENTRY_IFINDEX);
            break;

        case BASE_SFLOW_ENTRY_IF_NAME_IFNAME:
            if(entry->attr_set.contains(BASE_SFLOW_ENTRY_IFINDEX)){
                NAS_SFLOW_LOG(ERR,"Multiple Interface Index passed "
                            "for creating sFlow session");
                return false;
            }

            {
            auto * ifname = (const char *)cps_api_object_attr_data_bin(it.attr);
            interface_ctrl_t i;
            memset(&i,0,sizeof(i));
            strncpy(i.if_name,ifname,sizeof(i.if_name)-1);
            i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                EV_LOGGING(NAS_L2, DEBUG, "NAS-SFLOW","Can't get interface control information for %s",
                            ifname);
                return false;
            }
            entry->ifindex = i.if_index;
            entry->attr_set.add(BASE_SFLOW_ENTRY_IFINDEX);
            }
            break;

        case BASE_SFLOW_ENTRY_DIRECTION :
            if(entry->attr_set.contains(BASE_SFLOW_ENTRY_DIRECTION)){
                NAS_SFLOW_LOG(ERR,"Multiple Direction Attributes passed "
                                            "for creating sFlow session");
                return false;
            }
            entry->ndi_sflow_entry.sflow_direction = (BASE_CMN_TRAFFIC_PATH_t)
                                                        cps_api_object_attr_data_u32(it.attr);
            entry->attr_set.add(BASE_SFLOW_ENTRY_DIRECTION);
            break;

        case BASE_SFLOW_ENTRY_SAMPLING_RATE :
            if(entry->attr_set.contains(BASE_SFLOW_ENTRY_SAMPLING_RATE)){
                NAS_SFLOW_LOG(ERR,"Multiple Sampling Attributes passed "
                                           "for creating sFlow session");
                return false;
            }
            entry->ndi_sflow_entry.sampling_rate = cps_api_object_attr_data_u32(it.attr);
            entry->attr_set.add(BASE_SFLOW_ENTRY_SAMPLING_RATE);
            break;

        default:
            break;
        }
    }
    return nas_validate_sflow_entry(entry);
}


t_std_error nas_sflow_create_session(cps_api_object_t obj){

    nas_sflow_entry_t nas_sflow_entry;

    if(!nas_sflow_fill_session_info(obj,&nas_sflow_entry)){
        return STD_ERR(SFLOW,CFG,0);
    }

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = nas_sflow_entry.ifindex;

    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        NAS_SFLOW_LOG(ERR,"Interface %d has NO slot %d, port %d",
                intf_ctrl.if_index, intf_ctrl.npu_id, intf_ctrl.port_id);
        return STD_ERR(SFLOW,FAIL,0);
    }

    nas_sflow_entry.ndi_sflow_entry.port_id = intf_ctrl.port_id;
    nas_sflow_entry.ndi_sflow_entry.npu_id = intf_ctrl.npu_id;
    nas_sflow_entry.ndi_sflow_entry.enabled = true;

    std_mutex_simple_lock_guard lock(&nas_sflow_mutex);

    if(ndi_sflow_create_session(&(nas_sflow_entry.ndi_sflow_entry)) != STD_ERR_OK){
        return STD_ERR(SFLOW,FAIL,0);
    }

    if(!nas_sflow_update_direction(&nas_sflow_entry.ndi_sflow_entry,true)){
        NAS_SFLOW_LOG(ERR,"Failed to add source ports to session %lu",
                      nas_sflow_entry.ndi_sflow_entry.ndi_sflow_id);
        ndi_sflow_delete_session(&nas_sflow_entry.ndi_sflow_entry);
        return STD_ERR(SFLOW,FAIL,0);
    }

    nas_sflow_entry.nas_sflow_id= nas_sflow_get_next_index();
    cps_api_set_key_data(obj,BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32,
                         &nas_sflow_entry.nas_sflow_id,sizeof(nas_sflow_entry.nas_sflow_id));
    NAS_SFLOW_LOG(DEBUG,"Created new nas sflow entry with id %d",nas_sflow_entry.nas_sflow_id);
    nas_sflow_table->insert(nas_sflow_pair(nas_sflow_entry.nas_sflow_id,std::move(nas_sflow_entry)));

    return STD_ERR_OK;
}


t_std_error nas_sflow_delete_session(nas_sflow_id_t id){

    std_mutex_simple_lock_guard lock(&nas_sflow_mutex);
    nas_sflow_map_it it = nas_sflow_table->find(id);

    if(it == nas_sflow_table->end()) {
        NAS_SFLOW_LOG(ERR,"No NAS sFlow session with Id %d exist",(int)id);
        return STD_ERR(SFLOW,NEXIST,0);
    }
    ndi_sflow_entry_t * entry = &(it->second.ndi_sflow_entry);

    if(!nas_sflow_update_direction(entry,false)){
        NAS_SFLOW_LOG(ERR,"Failed to removed source ports from session %d",
                      it->second.nas_sflow_id);
        return STD_ERR(SFLOW,FAIL,0);
    }

    if(ndi_sflow_delete_session(entry) != STD_ERR_OK) {
        return STD_ERR(SFLOW,FAIL,0);
    }

    NAS_SFLOW_LOG(DEBUG,"Deleted nas sflow entry with id %d",it->second.nas_sflow_id);
    nas_sflow_remove_index(it->second.nas_sflow_id);
    nas_sflow_table->erase(it);
    return STD_ERR_OK;
}


t_std_error nas_sflow_update_session(cps_api_object_t obj, nas_sflow_id_t id){

    unsigned int prev_sampling_rate;
    std_mutex_simple_lock_guard lock(&nas_sflow_mutex);

    nas_sflow_map_it sit = nas_sflow_table->find(id);

    if(sit == nas_sflow_table->end()){
        NAS_SFLOW_LOG(ERR,"No NAS sFlow session with Id %d exist",(int)id);
        return STD_ERR(SFLOW,NEXIST,0);
    }
    nas_sflow_entry_t & sflow_entry =  sit->second;

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        int attr_id = (int) cps_api_object_attr_id(it.attr);

        switch (attr_id) {

        case BASE_SFLOW_ENTRY_DIRECTION :
            if(sflow_entry.ndi_sflow_entry.sflow_direction != (BASE_CMN_TRAFFIC_PATH_t)
                    cps_api_object_attr_data_u32(it.attr)){
                if(!nas_sflow_update_session_attr(&(sflow_entry.ndi_sflow_entry),
                        BASE_SFLOW_ENTRY_DIRECTION,cps_api_object_attr_data_u32(it.attr))){
                        return STD_ERR(SFLOW,FAIL,0);
                }
                sflow_entry.ndi_sflow_entry.sflow_direction = (BASE_CMN_TRAFFIC_PATH_t)
                                                   cps_api_object_attr_data_u32(it.attr);
                NAS_SFLOW_LOG(DEBUG,"Updated sFlow session %d direction to %d",sflow_entry.nas_sflow_id,
                            sflow_entry.ndi_sflow_entry.sflow_direction);
            }
            break;

        case BASE_SFLOW_ENTRY_SAMPLING_RATE :
            if(sflow_entry.ndi_sflow_entry.sampling_rate != cps_api_object_attr_data_u32(it.attr)){
                prev_sampling_rate = sflow_entry.ndi_sflow_entry.sampling_rate;
                sflow_entry.ndi_sflow_entry.sampling_rate = cps_api_object_attr_data_u32(it.attr);
                if(!nas_sflow_update_session_attr(&(sflow_entry.ndi_sflow_entry),
                        BASE_SFLOW_ENTRY_SAMPLING_RATE, cps_api_object_attr_data_u32(it.attr))){
                    sflow_entry.ndi_sflow_entry.sampling_rate = prev_sampling_rate;
                    return STD_ERR(SFLOW,FAIL,0);
                }
                NAS_SFLOW_LOG(DEBUG,"Updated sFlow session %d sampling rate to %d",sflow_entry.nas_sflow_id,
                                    sflow_entry.ndi_sflow_entry.sampling_rate);
            }
            break;

        default:
            break;
        }
    }
    return STD_ERR_OK;
}


static void nas_sflow_fill_object(cps_api_object_t obj,nas_sflow_map_it it){

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj,BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32,
                         &it->second.nas_sflow_id,sizeof(it->second.nas_sflow_id));
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_ID,it->second.nas_sflow_id);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_IFINDEX,it->second.ifindex);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_DIRECTION,
                                   it->second.ndi_sflow_entry.sflow_direction);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_SAMPLING_RATE,
                                   it->second.ndi_sflow_entry.sampling_rate);
}


t_std_error nas_sflow_get_all_info(cps_api_object_list_t list){
    std_mutex_simple_lock_guard lock(&nas_sflow_mutex);
    nas_sflow_map_it it = nas_sflow_table->begin();

    for ( ; it != nas_sflow_table->end() ; ++it){
        cps_api_object_t obj=cps_api_object_create();

        if(obj == NULL){
            NAS_SFLOW_LOG(ERR,"Failed to create new object");
            return STD_ERR(SFLOW,NOMEM,0);
        }

        if (!cps_api_object_list_append(list,obj)) {
            cps_api_object_delete(obj);
            return STD_ERR(SFLOW,FAIL,0);
        }

       nas_sflow_fill_object(obj,it);
    }
    return STD_ERR_OK;
}


t_std_error nas_sflow_get_session_info(cps_api_object_list_t list,nas_sflow_id_t id){

    std_mutex_simple_lock_guard lock(&nas_sflow_mutex);
    nas_sflow_map_it it = nas_sflow_table->find(id);

    if(it == nas_sflow_table->end()){
        NAS_SFLOW_LOG(ERR,"No NAS sFlow session with Id %d exist",(int)id);
        return STD_ERR(SFLOW,NEXIST,0);
    }

    cps_api_object_t obj=cps_api_object_create();

    if(obj == NULL){
        NAS_SFLOW_LOG(ERR,"Failed to create new object");
        return STD_ERR(SFLOW,NOMEM,0);
    }

    if (!cps_api_object_list_append(list,obj)) {
        cps_api_object_delete(obj);
        return STD_ERR(SFLOW,FAIL,0);
    }

    nas_sflow_fill_object(obj,it);
    return STD_ERR_OK;
}
