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
 * filename: nas_mac_cps.cpp
 */

#include "dell-base-l2-mac.h"
#include "dell-base-if-lag.h"
#include "dell-base-if-phy.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"

#include "dell-base-common.h"
#include "nas_mac_api.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "std_error_codes.h"
#include "nas_ndi_mac.h"
#include "nas_ndi_switch.h"
#include "hal_if_mapping.h"
#include "cps_api_interface_types.h"
#include "std_mutex_lock.h"
#include "nas_if_utils.h"
#include "std_thread_tools.h"

#include "cps_api_object.h"
#include "cps_api_object_category.h"
#include "cps_api_object_key.h"

/*
 * mutex used for nas mac module
 */
static std_mutex_lock_create_static_init_fast(nas_mac_mutex);

static bool mac_auto_flush=true;


static cps_api_return_code_t cps_nas_mac_get_function (void * context, cps_api_get_params_t * param, size_t ix) {
    cps_api_object_it_t it;
    hal_ifindex_t if_index = 0;
    uint16_t vlan_id = 0;
    cps_api_key_t key;
    uint16_t request_type = 0;
    bool static_type = false;
    bool static_type_set = false;
    size_t attr_len;

    hal_mac_addr_t mac_addr;
    memset(&mac_addr, 0, sizeof(hal_mac_addr_t));

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);
    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt) {
        cps_api_object_it_begin(filt,&it);
        for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
            int id = (int)cps_api_object_attr_id(it.attr);
            switch (id) {
                 case BASE_MAC_QUERY_VLAN:
                     vlan_id = cps_api_object_attr_data_u16(it.attr);
                     break;
                 case BASE_MAC_QUERY_MAC_ADDRESS:
                     attr_len = cps_api_object_attr_len(it.attr);
                     if (attr_len > sizeof(hal_mac_addr_t)) {
                        attr_len = sizeof(hal_mac_addr_t);
                     }
                     memcpy(&mac_addr, cps_api_object_attr_data_bin(it.attr), attr_len);
                     break;
                 case BASE_MAC_QUERY_IFINDEX:
                     if_index = cps_api_object_attr_data_u16(it.attr);
                     break;
                case BASE_MAC_QUERY_COUNT:
                    break;
                case BASE_MAC_QUERY_STATIC:
                    static_type = cps_api_object_attr_data_u16(it.attr);
                    static_type_set = true;
                    break;
                case  BASE_MAC_QUERY_REQUEST_TYPE:
                    request_type = cps_api_object_attr_data_u16(it.attr);
                    break;
                default :
                    break;
            }
        }
    }
    if (!cps_api_key_from_attr_with_qual(&key, BASE_MAC_QUERY_OBJ, cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(ERR,  "Key for getting MAC object is not valid");
        return (cps_api_return_code_t)STD_ERR(MAC,CFG,0);
    }

    switch (request_type) {
        case BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_VLAN:
            if (nas_mac_get_all_vlan_info(param->list, vlan_id, static_type) == STD_ERR_OK) {
                if (!static_type_set) {
                    if (nas_mac_get_all_vlan_info(param->list, vlan_id, !static_type) == STD_ERR_OK) {
                        return cps_api_ret_code_OK;
                    }
                } else {
                        return cps_api_ret_code_OK;
                }
            }
            NAS_MAC_LOG(ERR,  "error getting vlan based macs");
            break;
        case BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_ADDRESS:
            if (nas_mac_get_all_mac_info(param->list, mac_addr, static_type) == STD_ERR_OK) {
                if (!static_type_set) {
                    if (nas_mac_get_all_mac_info(param->list, mac_addr, !static_type) == STD_ERR_OK) {
                        return cps_api_ret_code_OK;
                    }
                } else {
                    return cps_api_ret_code_OK;
                }
            }
            NAS_MAC_LOG(ERR,  "error getting vlan based macs");
            break;
        case BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_INTERFACE:
            if (nas_mac_get_all_if_info(param->list, if_index, static_type) == STD_ERR_OK) {
                if (!static_type_set) {
                    if (nas_mac_get_all_if_info(param->list, if_index, !static_type) == STD_ERR_OK) {
                        return cps_api_ret_code_OK;
                    }
                } else {
                    return cps_api_ret_code_OK;
                }
            }
            NAS_MAC_LOG(ERR,  "error getting interface based macs");
            break;
        case BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_COUNT:
             if (nas_mac_get_consolidated_count(param->list,vlan_id, if_index, static_type, static_type_set) == STD_ERR_OK) {
                 return cps_api_ret_code_OK;
             }
             NAS_MAC_LOG(ERR,  "error getting count of macs");
             break;
         case BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_ALL:
         default:
             if (nas_mac_get_all_info(param->list, static_type) == STD_ERR_OK) {
                 if (!static_type_set) {
                     if (nas_mac_get_all_info(param->list, !static_type) == STD_ERR_OK) {
                         return cps_api_ret_code_OK;
                     }
                 } else {
                     return cps_api_ret_code_OK;
                 }
             }
             NAS_MAC_LOG(ERR,  "error getting all macs");
             break;
    }
    return cps_api_ret_code_ERR;
}


static cps_api_return_code_t cps_nas_mac_set_function(void * context, cps_api_transaction_params_t * param, size_t ix) {

    t_std_error rc;

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if( op == cps_api_oper_CREATE){
        if ((rc = nas_mac_cps_create_entry(obj))!= STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if ( op == cps_api_oper_CREATE || op == cps_api_oper_DELETE) {
        cps_api_object_t cloned = cps_api_object_create();
        cps_api_object_clone(cloned, obj);
        cps_api_object_list_append(param->prev, cloned);
    }

    if(op == cps_api_oper_DELETE ) {
        if((rc = nas_mac_cps_delete_entry(obj)) != STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        NAS_MAC_LOG(DEBUG,  "in update/set request handling ");
        if((rc = nas_mac_cps_update_entry(obj)) != STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}

static bool nas_mac_event_function_cb(cps_api_object_t obj, void *param) {

    /* TODO: Implementation */
    return true;
}

static void nas_mac_event_notification_cb(npu_id_t npu_id, ndi_mac_event_type_t mac_event, ndi_mac_entry_t *mac_entry, bool is_lag_index)
{
    nas_mac_entry_t nas_mac_entry;
    interface_ctrl_t intf_ctrl;
    hal_ifindex_t    lag_index;

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);
    if (!is_lag_index) {
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_PORT;
        intf_ctrl.npu_id = mac_entry->port_info.npu_id;
        intf_ctrl.port_id = mac_entry->port_info.npu_port;

        if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
            NAS_MAC_LOG(ERR, "NDI MAC Get interface DEBUG failed.");
            return;
        }
        nas_mac_entry.ifindex = intf_ctrl.if_index;
    } else {
        if (nas_get_lag_if_index(mac_entry->ndi_lag_id,
                                    &lag_index) != STD_ERR_OK) {
           NAS_MAC_LOG(ERR,
                   "Failed to get Lag Ifindex for ndi lag id 0x%x " , mac_entry->ndi_lag_id);
           return;
        }
        nas_mac_entry.ifindex = lag_index;
    }

   nas_mac_entry.entry_key.vlan_id = mac_entry->vlan_id;
   memcpy(nas_mac_entry.entry_key.mac_addr, mac_entry->mac_addr, sizeof(hal_mac_addr_t));
   nas_mac_entry.pkt_action = mac_entry->action;

    switch (mac_event) {
        case NDI_MAC_EVENT_LEARNED:
            nas_mac_create_entry(&nas_mac_entry, mac_entry->is_static, true);
            break;

        case NDI_MAC_EVENT_AGED:
        case NDI_MAC_EVENT_FLUSHED:
            {
                std_mutex_simple_lock_guard lock(nas_mac_get_request_mutex());
                nas_mac_delete_entry(&nas_mac_entry, mac_entry->is_static, true, true);
                std_condition_var_signal(nas_mac_get_request_cv());
            }
            break;
        case NDI_MAC_EVENT_INVALID:
            break;
    }

}

static cps_api_return_code_t nas_mac_flush_handler (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Invalid operation %d for flusing macs",op);
        return (cps_api_return_code_t)STD_ERR(MAC,PARAM,0);
    }

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    if(nas_mac_cps_flush_entry(obj)!= STD_ERR_OK){
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Failed to flush entries");
        return (cps_api_return_code_t)STD_ERR(MAC,FAIL,0);
    }

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_mac_flush_mgmt_set(void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_object_attr_t auto_flush_attr = cps_api_object_attr_get(obj,
                                        BASE_MAC_FLUSH_MANAGEMENT_ENABLE);

    if(auto_flush_attr == NULL){
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","No value passed to change auto mac management");
        return (cps_api_return_code_t)STD_ERR(MAC,FAIL,0);
    }

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    mac_auto_flush = (bool)cps_api_object_attr_data_u32(auto_flush_attr);
    EV_LOGGING(L2MAC,DEBUG,"NAS-MAC","Auto MAC management value set to %d",mac_auto_flush);

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_mac_flush_mgmt_get(void * context, cps_api_get_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(param->list);
    if (obj == NULL) {
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Failed to create/append new object to list");
        return (cps_api_return_code_t)STD_ERR(MAC, NOMEM, 0);
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_MAC_FLUSH_MANAGEMENT_OBJ,
                                                       cps_api_qualifier_TARGET);
    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    cps_api_object_attr_add_u32(obj, BASE_MAC_FLUSH_MANAGEMENT_ENABLE, mac_auto_flush);

    return cps_api_ret_code_OK;
}


static t_std_error cps_nas_mac_init(cps_api_operation_handle_t handle) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(ERR, "Could not translate %d to key %s,", (int)(BASE_MAC_TABLE_OBJ),
                cps_api_key_print(&f.key, buff, sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    NAS_MAC_LOG(DEBUG, "Registering for BASE_MAC_TABLE_OBJ %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = handle;
    f._write_function = cps_nas_mac_set_function;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }


    memset(&f,0,sizeof(f));

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_MAC_QUERY_OBJ, cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(ERR, "Could not translate %d to key %s,", (int)(BASE_MAC_QUERY_OBJ),
                cps_api_key_print(&f.key, buff, sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    NAS_MAC_LOG(DEBUG, "Registering for BASE_MAC_QUERY_OBJ %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = handle;
    f._read_function = cps_nas_mac_get_function;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_MAC_FLUSH_OBJ,
                                             cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(DEBUG, "Could not translate %d to key %s",
                     (int)(BASE_MAC_FLUSH_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    f.handle = handle;
    f._write_function = nas_mac_flush_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_MAC_FLUSH_MANAGEMENT_OBJ,
                                                cps_api_qualifier_TARGET)) {
       NAS_MAC_LOG(DEBUG, "Could not translate %d to key %s",
                   (int)(BASE_MAC_FLUSH_MANAGEMENT_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
       return STD_ERR(MAC,FAIL,0);
    }

    f.handle = handle;
    f._write_function = nas_mac_flush_mgmt_set;
    f._read_function = nas_mac_flush_mgmt_get;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}

static cps_api_return_code_t nas_mac_vlan_process_port_membership(cps_api_object_t obj, bool add_ports)
{
    cps_api_object_it_t it;

    uint32_t vlan_id = 0;
    hal_ifindex_t port_index = 0;

    if (add_ports) {
        NAS_MAC_LOG(DEBUG, "NAS Vlan port update for add, nothing to do, returning");
        return cps_api_ret_code_OK;
    }

    NAS_MAC_LOG(DEBUG, "NAS port vlan membership update");

    cps_api_object_it_begin(obj,&it);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);

        if(vlan_id_attr == NULL) {
            NAS_MAC_LOG(DEBUG, "Missing Vlan ID for CPS Set");
            return cps_api_ret_code_ERR;
        }

        vlan_id = (uint32_t) cps_api_object_attr_data_u32(vlan_id_attr);

        NAS_MAC_LOG(DEBUG, "Vlan index 0x%x", vlan_id);
        if (!vlan_id) {
            NAS_MAC_LOG(DEBUG, "Invalid Vlan index 0x%x, returning", vlan_id);
            return cps_api_ret_code_ERR;
        }

        cps_api_object_attr_t port_list_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);
        cps_api_object_attr_t tag_port_list_attr = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);

        if((port_list_attr == NULL) && (tag_port_list_attr == NULL)) {
           NAS_MAC_LOG(DEBUG, "Missing Port list for CPS Set");
           return cps_api_ret_code_ERR;
        }


        if (port_list_attr) {
            port_index = (hal_ifindex_t) cps_api_object_attr_data_u32(port_list_attr);
            NAS_MAC_LOG(DEBUG, "untagged port index %d", port_index);

            if (nas_mac_flush_vlan_entries_of_port(vlan_id, port_index) != STD_ERR_OK) {
                return cps_api_ret_code_ERR;
            }
        }
        if (tag_port_list_attr) {
            port_index = (hal_ifindex_t) cps_api_object_attr_data_u32(tag_port_list_attr);
            NAS_MAC_LOG(DEBUG, "tagged port index %d", port_index);

            if (nas_mac_flush_vlan_entries_of_port(vlan_id, port_index) != STD_ERR_OK) {
                return cps_api_ret_code_ERR;
            }
        }
    }
    return cps_api_ret_code_OK;
}

static bool nas_mac_vlan_event_cb(cps_api_object_t obj, void *param)
{
    NAS_MAC_LOG(DEBUG, "Received VLAN Port notification");

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    bool add_ports = false;

    if (op == cps_api_oper_CREATE) {
        NAS_MAC_LOG(DEBUG, "Received ADD VLAN operation code.. ");
        add_ports = true;
    } else if (op == cps_api_oper_DELETE) {
        NAS_MAC_LOG(DEBUG, "Received DEL VLAN operation code.. ");
    } else {
        NAS_MAC_LOG(DEBUG, "Received Invalid VLAN operation code, 0x%x", op);
        return cps_api_ret_code_ERR;
    }



    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    if(nas_mac_vlan_process_port_membership(obj, add_ports) != cps_api_ret_code_OK){
        return cps_api_ret_code_ERR;
    }

    NAS_MAC_LOG(DEBUG, "Port vlan membership event processing done .. ");
    return cps_api_ret_code_OK;
}

static bool nas_mac_if_event_cb(cps_api_object_t obj, void *param)
{
    NAS_MAC_LOG(DEBUG,"Interface event handling");

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG, "NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,IF_INTERFACES_STATE_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        return false;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t oper_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_OPER_STATUS);

    if(oper_attr == NULL){
        return false;
    }

    IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t oper_status = (IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t)
                                               cps_api_object_attr_data_u32(oper_attr);

    if(oper_status == IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_DOWN){
        std_mutex_simple_lock_guard lock(&nas_mac_mutex);
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on interface %d failed when it went oper down",index);
            return false;
        }
    }
    NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on an interface %d",index);

    return true;
}


t_std_error nas_mac_reg_if_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    cps_api_key_from_attr_with_qual(&key, DELL_BASE_IF_CMN_IF_INTERFACES_STATE_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_if_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for if events");
        return STD_ERR(MAC,FAIL,0);
    }
    return STD_ERR_OK;
}


static bool nas_mac_lag_event_cb(cps_api_object_t obj, void *param)
{

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        return false;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS);

    if(admin_attr == NULL){
        return false;
    }

    IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_t admin_status = (IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_t)
                                                                    cps_api_object_attr_data_u32(admin_attr);

    if(admin_status == IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_DOWN){
        std_mutex_simple_lock_guard lock(&nas_mac_mutex);
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on LAG interface %d failed when it went oper down",index);
            return false;
        }
        NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on LAG interface %d",index);
    }

    return true;
}


static bool nas_mac_lag_state_event_cb(cps_api_object_t obj, void *param)
{

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,IF_INTERFACES_STATE_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        return false;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t oper_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_OPER_STATUS);

    if(oper_attr == NULL){
        return false;
    }
    IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t oper_status = (IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t)
                                                                    cps_api_object_attr_data_u32(oper_attr);

    if(oper_status == IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_DOWN){
        std_mutex_simple_lock_guard lock(&nas_mac_mutex);
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on LAG interface %d failed when it went oper down",index);
            return false;
        }
        NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on LAG interface %d",index);
    }

    return true;
}


t_std_error nas_mac_reg_lag_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    cps_api_key_from_attr_with_qual(&key, BASE_IF_LAG_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_lag_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for lag events");
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&reg,0,sizeof(reg));
    cps_api_key_t lag_state_key;

    cps_api_key_from_attr_with_qual(&lag_state_key, BASE_IF_LAG_IF_INTERFACES_STATE_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &lag_state_key;

    if (cps_api_event_thread_reg(&reg, nas_mac_lag_state_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for lag events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_reg_vlan_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;

    memset(&reg,0,sizeof(reg));

    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not initialize the event service");
        return STD_ERR(MAC,FAIL,0);
    }

    if (cps_api_event_thread_init() != cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not initialize the event thread");
        return STD_ERR(MAC,FAIL,0);
    }

    cps_api_key_from_attr_with_qual(&key, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_vlan_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for vlan events");
        return STD_ERR(MAC,FAIL,0);
    }

    cps_api_key_from_attr_with_qual(&key, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_vlan_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for vlan events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_init(cps_api_operation_handle_t handle) {

    t_std_error rc = STD_ERR_OK;

    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    const unsigned int NUM_EVENTS=2;
    cps_api_key_t keys[NUM_EVENTS];

    cps_api_key_init(&keys[0],cps_api_qualifier_OBSERVED,(cps_api_object_category_types_t)cps_api_obj_CAT_BASE_MAC,
            BASE_MAC_TABLE_OBJ,0);
    cps_api_key_init(&keys[1],cps_api_qualifier_TARGET,(cps_api_object_category_types_t) cps_api_obj_CAT_BASE_MAC,
            BASE_MAC_TABLE_OBJ,0);

    reg.number_of_objects = NUM_EVENTS;
    reg.objects = keys;

    if (cps_api_event_thread_reg(&reg,nas_mac_event_function_cb,NULL)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = cps_nas_mac_init(handle)) != STD_ERR_OK){
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = ndi_mac_event_notify_register(nas_mac_event_notification_cb))!= STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = ndi_switch_mac_age_time_set(0, SWITCH_DEFAULT_MAC_AGE_TIMEOUT))!= STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_vlan_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_if_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_lag_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if((rc = nas_mac_event_handle_init() != STD_ERR_OK)){
        return rc;
    }

    std_thread_create_param_t nas_l2_mac_req_handler_thr;
    std_thread_init_struct(&nas_l2_mac_req_handler_thr);
    nas_l2_mac_req_handler_thr.name = "nas-l2-mac-req-handler";
    nas_l2_mac_req_handler_thr.thread_function = (std_thread_function_t)nas_l2_mac_req_handler;

    if (std_thread_create(&nas_l2_mac_req_handler_thr)!=STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Error creating nas mac request thread");
        return STD_ERR(MAC,FAIL,0);
    }

    NAS_MAC_LOG(DEBUG, "nas_mac_init: SUCCESS");

    return (rc);
}
