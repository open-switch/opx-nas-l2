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
 * filename: nas_mac_api.cpp
 */

#include "nas_mac_api.h"
#include "nas_switch.h"
#include "std_error_codes.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mac.h"
#include "nas_base_utils.h"
#include "nas_linux_l2.h"
#include "nas_if_utils.h"

#include <unordered_set>
#include <stdlib.h>


static bool nas_mac_entry_action_supported(BASE_MAC_PACKET_ACTION_t action)
{
    return (action == BASE_MAC_PACKET_ACTION_FORWARD ||
            action == BASE_MAC_PACKET_ACTION_LOG ||
            action == BASE_MAC_PACKET_ACTION_TRAP ||
            action == BASE_MAC_PACKET_ACTION_DROP);
}


static t_std_error nas_mac_obj_to_entry (cps_api_object_t obj, nas_mac_entry_t *entry) {

    cps_api_object_it_t it;
    bool valid_param_set[4] = {false, false, false, false};
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    memset(entry, 0, sizeof(nas_mac_entry_t));
    entry->npu_configured = true;
    entry->os_configured =false;
    entry->is_static = false;

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch ((int) cps_api_object_attr_id(it.attr)) {

            case BASE_MAC_TABLE_VLAN:
            case BASE_MAC_QUERY_VLAN:
                entry->entry_key.vlan_id = cps_api_object_attr_data_u16(it.attr);
                valid_param_set[1] = true;
                break;

            case BASE_MAC_TABLE_IFINDEX:
            case BASE_MAC_QUERY_IFINDEX:
                entry->ifindex = cps_api_object_attr_data_u32(it.attr);
                valid_param_set[2] = true;
                break;

            case BASE_MAC_TABLE_IFNAME:
            case BASE_MAC_QUERY_IFNAME:
            {
                const char * name = (const char *)cps_api_object_attr_data_bin(it.attr);
                interface_ctrl_t i;
                memset(&i,0,sizeof(i));
                strncpy(i.if_name,name,sizeof(i.if_name)-1);
                i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                    EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                            "Can't get interface control information for %s",name);
                        return STD_ERR(MAC,FAIL,0);
                }
                entry->ifindex = i.if_index;
                valid_param_set[2] = true;
                break;
            }
            case BASE_MAC_TABLE_MAC_ADDRESS:
            case BASE_MAC_QUERY_MAC_ADDRESS:
            {
                size_t mac_len = cps_api_object_attr_len(it.attr);
                if (mac_len < sizeof(hal_mac_addr_t)) {
                    NAS_MAC_LOG(ERR, "Invalid mac address format");
                    return STD_ERR(MAC,CFG,0);
                }
                memcpy(entry->entry_key.mac_addr, cps_api_object_attr_data_bin(it.attr),
                        sizeof(hal_mac_addr_t));
                valid_param_set[3] = true;
                break;
            }

            case BASE_MAC_TABLE_ACTIONS:
            {
                BASE_MAC_PACKET_ACTION_t pkt_action = (BASE_MAC_PACKET_ACTION_t)
                                                    cps_api_object_attr_data_u32(it.attr);
                if (!nas_mac_entry_action_supported(pkt_action)) {
                    NAS_MAC_LOG(ERR,  "Unsupported action type: %d", entry->pkt_action);
                    return STD_ERR(MAC,CFG,0);
                }
                else{
                    valid_param_set[0] = true;
                    entry->pkt_action = pkt_action;
                }
                break;
            }
            case BASE_MAC_QUERY_STATIC:
            case BASE_MAC_TABLE_STATIC:
                entry->is_static = cps_api_object_attr_data_u32(it.attr);
                break;

            case BASE_MAC_TABLE_CONFIGURE_OS:
                entry->os_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            case BASE_MAC_TABLE_CONFIGURE_NPU:
                entry->npu_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            default:
                break;
        }
    }

    if( op == cps_api_oper_CREATE){
        /* validate the params if it is a create request. */
        if ((!valid_param_set[1]) || (!valid_param_set[2]) || (!valid_param_set[3])) {
            NAS_MAC_LOG(ERR, "All the valid parameters(vlan/ifindex/mac)are not passed");
            return STD_ERR(MAC,CFG,0);
        }
        if (!valid_param_set[0]) {
            /* Use FORWARD as default action if not specified */
            entry->pkt_action = BASE_MAC_PACKET_ACTION_FORWARD;
        }
    } else if (op == cps_api_oper_SET) {
        /* validate the params if it is a set request. */
        if (!valid_param_set[1] || !valid_param_set[3]) {
            NAS_MAC_LOG(ERR, "All the valid parameters(vlan/mac)are not passed");
            return STD_ERR(MAC,CFG,0);
        }
    }
    return STD_ERR_OK;
}


t_std_error nas_mac_update_entry_in_os(nas_mac_entry_t *entry,
                                       cps_api_operation_types_t op){
     cps_api_object_guard og(cps_api_object_create());
     if(og.get() == nullptr) return STD_ERR(MAC,NOMEM,0);
     cps_api_object_set_type_operation(cps_api_object_key(og.get()),op);
     cps_api_object_attr_add_u32(og.get(),BASE_MAC_TABLE_IFINDEX,entry->ifindex);
     cps_api_object_attr_add_u32(og.get(),BASE_MAC_TABLE_STATIC,entry->is_static);
     cps_api_object_attr_add_u16(og.get(),BASE_MAC_TABLE_VLAN,entry->entry_key.vlan_id);
     cps_api_object_attr_add(og.get(),BASE_MAC_TABLE_MAC_ADDRESS,(void *)&entry->entry_key.mac_addr,
                                 sizeof(entry->entry_key.mac_addr));

     interface_ctrl_t intf_ctrl;
     memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

     intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
     intf_ctrl.if_index = entry->ifindex;

     if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
         cps_api_object_attr_add(og.get(),BASE_MAC_TABLE_IFNAME,(void *)intf_ctrl.if_name,
                                     strlen(intf_ctrl.if_name)+1);
     }
     t_std_error rc = nas_os_mac_update_entry(og.get());
     return rc;
}


static bool nas_mac_fill_ndi_entry(ndi_mac_entry_t & ndi_mac_entry,nas_mac_entry_t & entry ){
    if(entry.ifindex != 0){
        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = entry.ifindex;

        if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
            EV_LOGGING(L2MAC,ERR,"NAS-MAC", "Get interface info failed for ifindex %d.",entry.ifindex);
            return false;
        }

        ndi_obj_id_t obj_id;
        if (intf_ctrl.int_type == nas_int_type_LAG) {
            if (nas_mac_lag_obj_id_get(entry.ifindex, obj_id) == STD_ERR_OK) {
                ndi_mac_entry.ndi_lag_id = obj_id;
            }
        }
        ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
        ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
    }

    ndi_mac_entry.vlan_id = entry.entry_key.vlan_id;
    ndi_mac_entry.npu_id = 0;

    memcpy(ndi_mac_entry.mac_addr, entry.entry_key.mac_addr, sizeof(hal_mac_addr_t));
    ndi_mac_entry.is_static = entry.is_static;
    ndi_mac_entry.action = entry.pkt_action;
    return true;

}


static t_std_error nas_mac_create_entry_hw(nas_mac_entry_t *entry){

    ndi_mac_entry_t ndi_mac_entry;
    t_std_error rc;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));

    if(!nas_mac_fill_ndi_entry(ndi_mac_entry,*entry)){
        return STD_ERR(MAC,CFG,0);
    }

    if((rc = ndi_create_mac_entry(&ndi_mac_entry)) != STD_ERR_OK){
        return rc;
    }

    return STD_ERR_OK;
}


static void nas_mac_send_event_notification(nas_mac_entry_t & entry,nas_l2_mac_op_t op_type){
    unsigned int len = sizeof(nas_l2_event_header_t)+ sizeof(nas_mac_npu_event_t);
    void * data = calloc(len,sizeof(char));

    if(!data){
        NAS_MAC_LOG(ERR,"Failed to allocate memory for sending data to fd");
        return;
    }

    nas_mac_npu_event_t * mac_event = (nas_mac_npu_event_t *)((char *)data + sizeof(nas_l2_event_header_t));
    nas_l2_event_header_t *hdr = (nas_l2_event_header_t *)data;

    memcpy(&mac_event->entry,&entry,sizeof(entry));
    mac_event->op_type = op_type;

    hdr->ev_type = NAS_MAC_NPU_EVENT;
    hdr->len = 1;

    nas_mac_send_npu_event_notification(data,len);
    free(data);

}


t_std_error nas_mac_cps_create_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;

    if ((rc = nas_mac_obj_to_entry(obj, &entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }

    if(entry.os_configured==true){
        if((rc = nas_mac_update_entry_in_os(&entry,cps_api_oper_CREATE)) != STD_ERR_OK){
            return rc;
        }
    }

    if(entry.npu_configured == true){
        if((rc = nas_mac_create_entry_hw(&entry))!=STD_ERR_OK){
            return rc;
        }
        cps_api_object_attr_t _pub_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_PUBLISH);
        if(_pub_attr){
            bool _publish = cps_api_object_attr_data_u32(_pub_attr);
            if(_publish){
                nas_mac_send_event_notification(entry,NAS_MAC_ADD);
            }
        }


    }

    return STD_ERR_OK;
}

static t_std_error nas_mac_update_entry(nas_mac_entry_t *entry){

    t_std_error rc;
    ndi_mac_entry_t ndi_mac_entry;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));

    if(!nas_mac_fill_ndi_entry(ndi_mac_entry,*entry)){
        return STD_ERR(MAC,CFG,0);
    }

    if(entry->ifindex != 0){
        cps_api_operation_types_t op = cps_api_oper_DELETE;
        if(entry->os_configured==true){
            op = cps_api_oper_SET;
        }

        if((rc = nas_mac_update_entry_in_os(entry,op))!= STD_ERR_OK){
            return rc;
        }

        if(entry->npu_configured){
            if((rc = ndi_update_mac_entry(&ndi_mac_entry,NDI_MAC_ENTRY_ATTR_PORT_ID)) != STD_ERR_OK){
                return rc;
            }
        }
    }

    if(entry->pkt_action != 0){
        if((rc = ndi_update_mac_entry(&ndi_mac_entry,NDI_MAC_ENTRY_ATTR_PKT_ACTION)) != STD_ERR_OK){
            return rc;
        }
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_cps_update_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;
    memset(&entry, 0, sizeof(nas_mac_entry_t));

    if ((rc = nas_mac_obj_to_entry(obj, &entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }
    return nas_mac_update_entry(&entry);
}


static bool is_filter_type_present (nas_mac_entry_t *entry, del_filter_type_t filter_type) {
    hal_mac_addr_t zero_mac;
    memset(&zero_mac, 0, sizeof(hal_mac_addr_t));
    switch (filter_type) {
        case DEL_VLAN_FILTER:
            if (entry->entry_key.vlan_id != 0) {
                return true;
            }
            break;
        case DEL_MAC_FILTER:
            if (memcmp(entry->entry_key.mac_addr, zero_mac, sizeof(hal_mac_addr_t)) != 0) {
                return true;
            }
            break;
        case DEL_IF_FILTER:
            if (entry->ifindex != 0) {
                return true;
            }
            break;
        default :
            break;
    }
    return false;
}


static void nas_mac_fill_flush_entry (nas_mac_cps_event_t & flush_entry) {

    bool vlan_filter_on, mac_filter_on, if_filter_on = false;
    bool single_entry_delete = false;
    ndi_mac_delete_type_t del_type = NDI_MAC_DEL_ALL_ENTRIES;

    vlan_filter_on = is_filter_type_present(&flush_entry.entry, DEL_VLAN_FILTER);
    mac_filter_on = is_filter_type_present(&flush_entry.entry, DEL_MAC_FILTER);
    if_filter_on = is_filter_type_present(&flush_entry.entry, DEL_IF_FILTER);
    single_entry_delete  = ((vlan_filter_on) && (mac_filter_on));

    if(single_entry_delete){
        if(flush_entry.entry.os_configured == true){
            nas_mac_update_entry_in_os(&flush_entry.entry,cps_api_oper_DELETE);
            if(flush_entry.entry.npu_configured == false){
                return;
            }
        }
        del_type = NDI_MAC_DEL_SINGLE_ENTRY;
    }else if (if_filter_on) {
        del_type = NDI_MAC_DEL_BY_PORT;
        if(vlan_filter_on) del_type = NDI_MAC_DEL_BY_PORT_VLAN;
    } else if (vlan_filter_on) {
        del_type = NDI_MAC_DEL_BY_VLAN;
    }


    flush_entry.op_type = NAS_MAC_DEL;
    flush_entry.del_type = del_type;
    flush_entry.subtype_all = flush_entry.entry.is_static ? true : false;

    return;
}


t_std_error nas_mac_send_cps_event(nas_mac_cps_event_t * entry, int count){
    int cps_event_len = count * sizeof(nas_mac_cps_event_t);
    int len = sizeof(nas_l2_event_header_t) + cps_event_len;
    void * data = calloc(len,sizeof(char));
    if(data){
        nas_l2_event_header_t *hdr = (nas_l2_event_header_t *)data;
        hdr->ev_type = NAS_MAC_CPS_EVENT;
        hdr->len = count;
        nas_mac_cps_event_t * mac_event = (nas_mac_cps_event_t *)((char *)data + sizeof(nas_l2_event_header_t));
        memcpy((void  *)mac_event,(void *)entry,cps_event_len);
        nas_mac_send_cps_event_notification(data,len);
        free(data);
        return STD_ERR_OK;
    }

    return STD_ERR(MAC,FAIL,0);
}


t_std_error nas_mac_cps_delete_entry (cps_api_object_t obj){

    nas_mac_cps_event_t flush_entry;
    t_std_error rc;
    if ((rc = nas_mac_obj_to_entry(obj, &flush_entry.entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Object to Entry conversion failed ");
        return rc;
    }
    nas_mac_fill_flush_entry(flush_entry);
    return nas_mac_send_cps_event(&flush_entry,1);

}


t_std_error nas_mac_flush_vlan_entries_of_port(uint32_t vlan, hal_ifindex_t port_index) {

    nas_mac_cps_event_t flush_entry;
    memset(&flush_entry.entry, 0, sizeof(nas_mac_entry_t));
    flush_entry.entry.ifindex = port_index;
    flush_entry.entry.entry_key.vlan_id = vlan;
    nas_mac_fill_flush_entry(flush_entry);
    return nas_mac_send_cps_event(&flush_entry,1);
}


static bool nas_mac_flush_entries(cps_api_object_t obj,const cps_api_object_it_t & it){

    cps_api_object_it_t it_lvl_1 = it;
    cps_api_attr_id_t ids[3] = {BASE_MAC_FLUSH_INPUT_FILTER,0, BASE_MAC_FLUSH_INPUT_FILTER_VLAN };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    nas_mac_cps_event_t flush_entry;
    std::vector<nas_mac_cps_event_t> flush_queue;

    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        memset(&flush_entry,0,sizeof(nas_mac_cps_event_t));
        ids[1] = cps_api_object_attr_id (it_lvl_1.attr);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_VLAN;
        cps_api_object_attr_t vlan_attr = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFINDEX;
        cps_api_object_attr_t ifindex_attr = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFNAME;
        cps_api_object_attr_t ifname_attr = cps_api_object_e_get(obj,ids,ids_len);

        if(vlan_attr == NULL && ifindex_attr == NULL){
            continue;
        }

        if(vlan_attr){
            flush_entry.entry.entry_key.vlan_id = cps_api_object_attr_data_u16(vlan_attr);
        }

        if(ifindex_attr){
            flush_entry.entry.ifindex = cps_api_object_attr_data_u32(ifindex_attr);
        }

        if(ifname_attr){
             const char * name = (const char *)cps_api_object_attr_data_bin(ifname_attr);
             interface_ctrl_t i;
             memset(&i,0,sizeof(interface_ctrl_t));
             strncpy(i.if_name,name,sizeof(i.if_name)-1);
             i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
             if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                 EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                     "Can't get interface control information for %s",name);
                      return false;
             }
             flush_entry.entry.ifindex = i.if_index;
        }

        nas_mac_fill_flush_entry(flush_entry);
        flush_queue.push_back(flush_entry);
    }

    return nas_mac_send_cps_event(&flush_queue[0],flush_queue.size()) == STD_ERR_OK ? true : false;

}


t_std_error nas_mac_cps_flush_entry(cps_api_object_t obj){

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {

        case BASE_MAC_FLUSH_INPUT_FILTER:
            if(!nas_mac_flush_entries(obj,it)){
                return STD_ERR(MAC,FAIL,0);
            }
            break;

        default:
            break;
        }
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_handle_if_down(hal_ifindex_t ifindex){

    nas_mac_cps_event_t flush_entry;
    memset(&flush_entry.entry, 0, sizeof(nas_mac_entry_t));
    flush_entry.entry.ifindex = ifindex;
    nas_mac_fill_flush_entry(flush_entry);
    return nas_mac_send_cps_event(&flush_entry,1);
}

static auto ndi_to_nas_mac_ev = new std::unordered_map<unsigned int,unsigned int>
{
    {NDI_MAC_EVENT_LEARNED, NAS_MAC_ADD},
    {NDI_MAC_EVENT_AGED,NAS_MAC_DEL},
    {NDI_MAC_EVENT_FLUSHED,NAS_MAC_FLUSH},
    {NDI_MAC_EVENT_MOVED,NAS_MAC_MOVE}
};

void nas_mac_event_notification_cb(npu_id_t npu_id, ndi_mac_event_type_t ev_type, ndi_mac_entry_t *mac_entry, bool is_lag_index)
{
    if(ev_type == NDI_MAC_EVENT_INVALID) return;

    nas_mac_npu_event_t  mac_event;
    memset(&mac_event,0,sizeof(mac_event));
    interface_ctrl_t intf_ctrl;
    hal_ifindex_t lag_index;

    if (!is_lag_index) {
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

        intf_ctrl.q_type = HAL_INTF_INFO_FROM_PORT;
        intf_ctrl.npu_id = mac_entry->port_info.npu_id;
        intf_ctrl.port_id = mac_entry->port_info.npu_port;

        if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
            NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
            return;
        }
        mac_event.entry.ifindex = intf_ctrl.if_index;
    } else {
        if (nas_get_lag_if_index(mac_entry->ndi_lag_id,&lag_index) != STD_ERR_OK) {
            NAS_MAC_LOG(ERR,"Failed to get Lag ifindex for ndi lag id 0x%x",mac_entry->ndi_lag_id);
            return;
        }
        mac_event.entry.ifindex = lag_index;
    }

    mac_event.entry.entry_key.vlan_id = mac_entry->vlan_id;
    memcpy(mac_event.entry.entry_key.mac_addr, mac_entry->mac_addr, sizeof(hal_mac_addr_t));
    mac_event.entry.pkt_action = mac_entry->action;

    auto it = ndi_to_nas_mac_ev->find(ev_type);
    if(it != ndi_to_nas_mac_ev->end()){
        mac_event.op_type = (nas_l2_mac_op_t)it->second;
    }else{
        NAS_MAC_LOG(ERR,"Invalid NDI event type %d",ev_type);
        return;
    }


    nas_mac_send_event_notification(mac_event.entry,mac_event.op_type);
}


bool nas_get_mac_entry_from_ndi(nas_mac_entry_t & entry){
    /*
     * For now you can only do a single entry get based on the key of the entry
     */

    ndi_mac_entry_t ndi_entry;
    memset(&ndi_entry,0,sizeof(ndi_entry));
    ndi_entry.vlan_id= entry.entry_key.vlan_id;
    memcpy(&ndi_entry.mac_addr,&entry.entry_key.mac_addr,sizeof(ndi_entry.mac_addr));

    if(ndi_get_mac_entry_attr(&ndi_entry) != STD_ERR_OK){
        NAS_MAC_LOG(ERR,"Failed to get MAC entry from NDI");
        return false;
    }

    entry.pkt_action = ndi_entry.action;
    entry.is_static = ndi_entry.is_static;
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));


    intf_ctrl.q_type = HAL_INTF_INFO_FROM_PORT;
    intf_ctrl.npu_id = ndi_entry.port_info.npu_id;
    intf_ctrl.port_id = ndi_entry.port_info.npu_port;

    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
        return false;
    }
    entry.ifindex = intf_ctrl.if_index;

    return true;
}

