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

static cps_api_event_service_handle_t handle;

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
        cps_api_object_delete(obj);
        return (t_std_error)rc;
    }
    cps_api_object_delete(obj);
    return STD_ERR_OK;
}

t_std_error nas_mac_publish_entry(nas_mac_entry_t *entry,bool is_static,bool flush_all,
                                  cps_api_operation_types_t op){

    if(entry == nullptr){
        NAS_MAC_LOG(ERR,"Null MAC entry pointer passed to convert it to cps object");
        return STD_ERR(MAC,PARAM,0);
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == nullptr){
        NAS_MAC_LOG(ERR,"Failed to allocate memory to cps object");
        return STD_ERR(MAC,NOMEM,0);
    }
    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(&key,op);
    cps_api_object_set_key(obj,&key);

    if(!flush_all){
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX,entry->ifindex);
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_ACTIONS,entry->pkt_action);
        cps_api_object_attr_add_u16(obj,BASE_MAC_TABLE_VLAN,entry->entry_key.vlan_id);
        cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS,(void*)entry->entry_key.mac_addr,
                                sizeof(entry->entry_key.mac_addr));
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_STATIC,is_static);

        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = entry->ifindex;

        if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
            cps_api_object_attr_add(obj, BASE_MAC_TABLE_IFNAME, (const void *)intf_ctrl.if_name,
                                    strlen(intf_ctrl.if_name)+1);
        }

    }

    NAS_MAC_LOG(INFO,"Publishing an event with operation %d",op);
    return nas_mac_event_publish(obj);

}

