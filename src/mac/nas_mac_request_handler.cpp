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
#include "std_error_codes.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mac.h"
#include "nas_if_utils.h"
#include <unistd.h>

static nas_mac_request_queue_t nas_mac_request_queue;
static std_condition_var_t nas_mac_request_cv;
static std_mutex_lock_create_static_init_fast(nas_mac_request_mutex);

std_mutex_type_t * nas_mac_get_request_mutex(void){
    return &nas_mac_request_mutex;
}

nas_mac_request_queue_t & nas_mac_get_request_queue(void){
    return nas_mac_request_queue;
}

std_condition_var_t * nas_mac_get_request_cv(void){
    return &nas_mac_request_cv;
}


t_std_error nas_mac_lag_obj_id_get (hal_ifindex_t if_index, ndi_obj_id_t& obj_id)
{
    nas::ndi_obj_id_table_t tmp_ndi_oid_tbl;
    if (dn_nas_lag_get_ndi_ids (if_index, &tmp_ndi_oid_tbl) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR,  "Lag object get failed for %d", if_index);
        return STD_ERR(MAC,NEXIST,0);
    }
    /* TODO - Handle multiple NPU scenerio */
    obj_id = tmp_ndi_oid_tbl[0];
    return STD_ERR_OK;
}


t_std_error nas_mac_delete_entries_from_hw(nas_mac_entry_t *entry, bool static_type,
                                           ndi_mac_delete_type_t del_type,
                                           bool subtype_all) {
    t_std_error rc = STD_ERR_OK;
    ndi_obj_id_t obj_id;
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = entry->ifindex;

    ndi_mac_entry_t ndi_mac_entry;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry_t));

    if ((del_type == NDI_MAC_DEL_BY_PORT) || (del_type == NDI_MAC_DEL_BY_PORT_VLAN))
    {
        if ((rc = dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
             NAS_MAC_LOG(ERR, "Get interface info failed for if index 0x%x.", entry->ifindex);
             return rc;
        }
        if(intf_ctrl.int_type == nas_int_type_LAG)
        {
           if(nas_mac_lag_obj_id_get(entry->ifindex, obj_id) == STD_ERR_OK)
           {
              ndi_mac_entry.ndi_lag_id = obj_id;
           }
        }
        else
        {
           ndi_mac_entry.npu_id = 0; /* TODO: Handle multiple NPU scenerio */
           ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
           ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
        }
    }

    ndi_mac_entry.vlan_id = entry->entry_key.vlan_id;

    if (del_type == NDI_MAC_DEL_SINGLE_ENTRY) {
        memcpy(ndi_mac_entry.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));
    }
    ndi_mac_entry.is_static = static_type;

    if ((rc = ndi_delete_mac_entry(&ndi_mac_entry, del_type, subtype_all) != STD_ERR_OK)) {
        NAS_MAC_LOG(ERR, "Error deleting NDI MAC entry with vlan id %d",
            entry->entry_key.vlan_id);
        return rc;
    }
    return STD_ERR_OK;
}

/* @TODO send an notification when flush is done */
void nas_l2_mac_req_handler(void){
    std_condition_var_init(&nas_mac_request_cv);

    while(1){
        std_mutex_lock(&nas_mac_request_mutex);
        while(nas_mac_request_queue.size() == 0 ){
            std_condition_var_wait(&nas_mac_request_cv,&nas_mac_request_mutex);
        }
        nas_mac_request_entry_t & req_entry = nas_mac_request_queue.front();
        if(req_entry.op_type == NAS_MAC_DEL){
            if(nas_mac_delete_entries_from_hw(&(req_entry.entry),req_entry.static_type,
                                              req_entry.del_type,req_entry.subtype_all)
                                             != STD_ERR_OK){
                NAS_MAC_LOG(ERR,"Failed to remove MAC entry from hardware");
            }
        }
        nas_mac_request_queue.pop();
        std_mutex_unlock(&nas_mac_request_mutex);
        /*
         * Sleep for 30 ms between consecutive flush calls to let bcm tx/rx thread get scheduled and
         * prevent XSTP from being changing the roots and settle down the topology
         *
         * @TODO - Get rid of this when SAI optimizes the flush time
         */
        usleep(30000);
    }

}
