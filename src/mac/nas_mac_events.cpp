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

#include "nas_mac_api.h"
#include "dell-base-l2-mac.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "std_error_codes.h"

#include "cps_api_object.h"
#include "cps_api_object_category.h"
#include "cps_api_object_key.h"
#include "hal_if_mapping.h"
#include "dell-base-l2-mac.h"

static cps_api_event_service_handle_t handle;
static unsigned int max_pub_thresold = 40;
static unsigned int max_obj_pub_thresold = 1000;

t_std_error nas_mac_event_handle_init(){

    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        return false;
    }

    if (cps_api_event_client_connect(&handle) != cps_api_ret_code_OK) {
        return false;
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_event_publish(cps_api_object_t obj){
    cps_api_return_code_t rc;
    if((rc = cps_api_event_publish(handle,obj))!= cps_api_ret_code_OK){
        EV_LOGGING(L2MAC,ERR,"MAC-EV-PUB","Failed to publish MAC event");
        cps_api_object_delete(obj);
        return (t_std_error)rc;
    }
    cps_api_object_delete(obj);
    return STD_ERR_OK;
}

static auto nas_to_pub_ev_type = new std::unordered_map<unsigned int,unsigned int>{
    {NAS_MAC_ADD,BASE_MAC_MAC_EVENT_TYPE_LEARNT},
    {NAS_MAC_DEL,BASE_MAC_MAC_EVENT_TYPE_AGED},
    {NAS_MAC_FLUSH,BASE_MAC_MAC_EVENT_TYPE_FLUSHED},
    {NAS_MAC_MOVE,BASE_MAC_MAC_EVENT_TYPE_MOVED}
};

void nas_mac_add_event_entry_to_obj(cps_api_object_t obj,nas_mac_entry_t & entry,nas_l2_mac_op_t add, unsigned int index){

    BASE_MAC_MAC_EVENT_TYPE_t ev_type;
    auto it = nas_to_pub_ev_type->find(add);

    if(it != nas_to_pub_ev_type->end()){
        ev_type = (BASE_MAC_MAC_EVENT_TYPE_t)it->second;
    }else{
        NAS_MAC_LOG(ERR,"Invalid nas l2 mac op %d for publishing events",add);
        return;
    }

    if(ev_type == BASE_MAC_MAC_EVENT_TYPE_AGED){
        nas_mac_update_entry_in_os(&entry,cps_api_oper_DELETE);
    }else if (ev_type == BASE_MAC_MAC_EVENT_TYPE_MOVED){
        nas_mac_update_entry_in_os(&entry,cps_api_oper_SET);
    }

    cps_api_attr_id_t ids[3] = {BASE_MAC_LIST_ENTRIES, index,BASE_MAC_LIST_ENTRIES_IFINDEX };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&entry.ifindex,sizeof(entry.ifindex));
    ids[2] = BASE_MAC_LIST_ENTRIES_ACTIONS;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&entry.pkt_action,sizeof(entry.pkt_action));
    ids[2] = BASE_MAC_LIST_ENTRIES_VLAN;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U16,&entry.entry_key.vlan_id,
                     sizeof(entry.entry_key.vlan_id));
    ids[2] = BASE_MAC_LIST_ENTRIES_MAC_ADDRESS;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,(void*)&entry.entry_key.mac_addr,
         sizeof(entry.entry_key.mac_addr));
    ids[2] = BASE_MAC_LIST_ENTRIES_STATIC;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,&entry.is_static,sizeof(entry.is_static));

    ids[2] = BASE_MAC_LIST_ENTRIES_EVENT_TYPE;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ev_type,sizeof(ev_type));


    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = entry.ifindex;

    if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
     ids[2] = BASE_MAC_LIST_ENTRIES_IFNAME;
     cps_api_object_e_add(obj,ids ,ids_len,cps_api_object_ATTR_T_BIN, (const void *)intf_ctrl.if_name,
                                strlen(intf_ctrl.if_name)+1);
    }

}


bool nas_mac_process_pub_queue(){

    nas_mac_npu_event_queue_t & ev_queue = nas_mac_get_npu_event_queue();
    unsigned int count = 0;
    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_LIST_OBJ,
                                       cps_api_qualifier_OBSERVED);
    unsigned int entry_count = 0;
    while(ev_queue.size() > 0 && count < max_obj_pub_thresold){
        cps_api_object_t obj = cps_api_object_create();
        if(obj == nullptr){
            NAS_MAC_LOG(ERR,"Failed to allocate memory for mac event publish");
            return false;
        }
        cps_api_object_set_key(obj,&key);
        while(entry_count < max_pub_thresold && ev_queue.size() > 0){
            nas_mac_npu_event_t & event = ev_queue.front();
            nas_mac_add_event_entry_to_obj(obj,event.entry,event.op_type,entry_count++);
            ev_queue.pop_front();
        }
        count += entry_count;
        entry_count=0;
        nas_mac_event_publish(obj);

    }
    return true;
}

