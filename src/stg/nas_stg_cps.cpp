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
 * filename: nas_stg_cps.cpp
 */


#include "dell-base-stg.h"
#include "dell-base-if-lag.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "std_error_codes.h"
#include "nas_stg_api.h"
#include "cps_api_interface_types.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "dell-base-if-linux.h"

static bool nas_stg_event_function_cb(cps_api_object_t obj, void *param) {

    cps_api_attr_id_t ids[2] = {BASE_STG_ENTRY_INTF, BASE_STG_ENTRY_INTF_STATE };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_attr_t stp_state = cps_api_object_e_get(obj,ids,ids_len);

    ids[1] = BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
    cps_api_object_attr_t ifindex = cps_api_object_e_get(obj,ids,ids_len);

    cps_api_object_attr_t type = cps_api_object_attr_get(obj,cps_api_if_STRUCT_A_IF_TYPE);
    cps_api_object_attr_t master = cps_api_object_attr_get(obj,BASE_IF_LINUX_IF_INTERFACES_INTERFACE_IF_MASTER);
    cps_api_object_attr_t vid = cps_api_object_attr_get(obj,BASE_STG_ENTRY_VLAN);
    cps_api_object_attr_t op = cps_api_object_attr_get(obj,cps_api_if_STRUCT_A_OPERATION);

    if (master != NULL &&  stp_state != NULL && ifindex != NULL) {
        hal_ifindex_t bridge_id = cps_api_object_attr_data_u32(master);
        hal_ifindex_t intf_index = cps_api_object_attr_data_u32(ifindex);
        unsigned int state = cps_api_object_attr_data_u32(stp_state);

        NAS_STG_LOG(DEBUG,"Setting stp state to %d for Bridge %d and Interface %d",
        state,bridge_id,intf_index);

        if(nas_stg_update_stg_state(bridge_id,intf_index, state) != STD_ERR_OK){
            return false;
        }
        return true;
    }

    if (type!=NULL && master != NULL && vid != NULL) {
        hal_ifindex_t bridge_id = cps_api_object_attr_data_u32(master);
        hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(vid);
        if(nas_stg_add_vlan_to_bridge(bridge_id,vlan_id) != STD_ERR_OK){
            return false;
        }
    }

    if(op != NULL && master != NULL && cps_api_object_attr_data_u32(op) == DB_INTERFACE_OP_DELETE){
        hal_ifindex_t bridge_id = cps_api_object_attr_data_u32(master);
        if(nas_stg_delete_instance(bridge_id) != STD_ERR_OK){
            return false;
        }
    }

    return true;
}

static cps_api_return_code_t cps_nas_default_stg_get_function (void * context,
                                cps_api_get_params_t * param, size_t ix) {
    return  nas_stg_get_default_instance(param->list);
}


static cps_api_return_code_t cps_nas_stg_get_function (void * context,
                                cps_api_get_params_t * param, size_t ix) {

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    cps_api_object_attr_t stg_id_attr = cps_api_get_key_data(filt,BASE_STG_ENTRY_ID);
    cps_api_object_attr_t def_stg_id_attr = cps_api_get_key_data(filt,BASE_STG_DEFAULT_STG_ID);
    cps_api_object_it_t it;
    cps_api_object_it_t* intf_it = NULL;
    nas_stg_port_list_t intf_list;

    t_std_error rc;

    if(def_stg_id_attr != NULL){

        return  (rc = (nas_stg_get_default_instance(param->list) != STD_ERR_OK)) ?
                     (cps_api_return_code_t)rc : cps_api_ret_code_OK;
    }

    if(stg_id_attr == NULL){
        return (rc = nas_stg_get_all_info(param->list)) != STD_ERR_OK ?
                     (cps_api_return_code_t)rc : cps_api_ret_code_OK;
    }

    cps_api_object_it_begin(filt, &it);
    for(; cps_api_object_it_valid(&it); cps_api_object_it_next(&it)) {
        int id = (int)cps_api_object_attr_id(it.attr);
        if (id == BASE_STG_ENTRY_INTF) {
            intf_it = &it;
            break;
        }
    }
    if (intf_it != NULL) {
        cps_api_object_it_t it_ins = *intf_it;
        cps_api_object_attr_t ifindex_attr;
        cps_api_attr_id_t ids[3] = {BASE_STG_ENTRY_INTF, 0, BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX};
        const int ids_len = sizeof(ids) / sizeof(ids[0]);
        for (cps_api_object_it_inside(&it_ins); cps_api_object_it_valid(&it_ins);
             cps_api_object_it_next(&it_ins)) {
            ids[1] = cps_api_object_attr_id(it_ins.attr);
            ifindex_attr = cps_api_object_e_get(filt, ids, ids_len);
            if (ifindex_attr != NULL) {
                intf_list.insert(cps_api_object_attr_data_u32(ifindex_attr));
            }
        }
    }

    nas_stg_id_t stg_id = cps_api_object_attr_data_u32(stg_id_attr);
    return (rc = nas_stg_get_instance_info(param->list,stg_id,&intf_list)!= STD_ERR_OK) ?
                 (cps_api_return_code_t)rc : cps_api_ret_code_OK;
}


static cps_api_return_code_t cps_nas_stg_set_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_stg_id_t stg_id = 0;
    t_std_error rc;

    if( op == cps_api_oper_CREATE){
        if((rc = nas_stg_cps_create_instance(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_CREATE ) {
        cps_api_object_t cloned = cps_api_object_create();
        if( cloned == NULL){
            NAS_STG_LOG(ERR,"Failed to create a new object");
            return (cps_api_return_code_t)STD_ERR(STG,NOMEM,0);
        }
        cps_api_object_clone(cloned,obj);
        cps_api_object_list_append(param->prev,cloned);
    }

    if(op == cps_api_oper_DELETE || op == cps_api_oper_SET ){
        cps_api_object_attr_t stg_id_attr;
        if ((stg_id_attr = cps_api_get_key_data(obj,BASE_STG_ENTRY_ID)) == NULL) {
            NAS_STG_LOG(ERR,"No STG id passed for Updating/deleting STG session");
            return (cps_api_return_code_t)STD_ERR(STG,CFG,0);
        }
        stg_id = cps_api_object_attr_data_u32(stg_id_attr);

        if((rc = nas_stg_get_instance_info(param->prev,stg_id,NULL)) != STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE){
        if((rc = nas_stg_cps_delete_instance(stg_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_stg_set_instance(obj,stg_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t cps_nas_default_stg_set_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix) {
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    t_std_error rc;
    if( op == cps_api_oper_SET){
        if((rc = nas_stg_set_default_instance_state(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

   return cps_api_ret_code_OK;
}


static cps_api_return_code_t cps_nas_stg_rollback_function (void * context,
                             cps_api_transaction_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_get(param->prev,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_stg_id_t stg_id = 0;
    t_std_error rc;

    if(op == cps_api_oper_CREATE || op == cps_api_oper_SET ){
        cps_api_object_attr_t stg_id_attr;
        if ((stg_id_attr = cps_api_get_key_data(obj,BASE_STG_ENTRY_ID)) == NULL) {
            NAS_STG_LOG(ERR,"No STG id passed for Updating/deleting STG session");
            return (cps_api_return_code_t)STD_ERR(STG,CFG,0);
        }
        stg_id = cps_api_object_attr_data_u32(stg_id_attr);
    }

    if( op == cps_api_oper_CREATE){
        if((rc = nas_stg_cps_delete_instance(stg_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE){
        if((rc = nas_stg_cps_create_instance(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_stg_set_instance(obj,stg_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t cps_nas_stg_vlan_set_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    nas_stg_id_t stg_id;
    cps_api_object_attr_t stg_id_attr;
    if ((stg_id_attr = cps_api_get_key_data(obj,BASE_STG_ENTRY_ID)) == NULL) {
        NAS_STG_LOG(ERR,"No STG id passed for Updating/deleting STG session");
        return (cps_api_return_code_t)STD_ERR(STG,CFG,0);
    }
    stg_id = cps_api_object_attr_data_u32(stg_id_attr);

    if ((op != cps_api_oper_CREATE) && (op != cps_api_oper_DELETE)){
        NAS_STG_LOG(ERR,"Invalid operation for vlan leaf-list");
        return (cps_api_return_code_t)STD_ERR(STG,PARAM,0);;
    }

    bool add=false;

    if( op == cps_api_oper_CREATE){
        add = true;
    }

    t_std_error rc;
    if((rc = nas_stg_update_vlans(obj,stg_id,add)) != STD_ERR_OK){
        return (cps_api_return_code_t)rc;
    }

    return cps_api_ret_code_OK;
}


bool nas_stg_process_lag_events(cps_api_object_t obj, void *param) {

    cps_api_object_attr_t lag_attr = cps_api_get_key_data(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if (lag_attr == NULL) {
        NAS_STG_LOG(ERR,"No LAG Interface Index passed to process LAG updates");
        return false;
    }

    hal_ifindex_t ifindex = (hal_ifindex_t)cps_api_object_attr_data_u32(lag_attr);
    return (nas_stg_lag_update(ifindex,obj) != STD_ERR_OK) ? false: true;
}


bool nas_stg_process_vlan_events(cps_api_object_t obj, void *param) {

    cps_api_object_attr_t vlan_attr = cps_api_get_key_data(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t tag_attr = cps_api_get_key_data(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS);
    cps_api_object_attr_t untag_attr = cps_api_get_key_data(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS);
    cps_api_object_attr_t bridge_attr = cps_api_get_key_data(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if (vlan_attr == NULL) {
        NAS_STG_LOG(ERR,"No VLAN ID passed to process VLAN updates");
        return false;
    }

    hal_ifindex_t bridge_ifindex = 0;
    if(bridge_attr != NULL){
        bridge_ifindex = (hal_ifindex_t)cps_api_object_attr_data_u32(bridge_attr);
    }

    bool create = false;
    cps_api_operation_types_t op = cps_api_object_type_operation (cps_api_object_key (obj));

    if (op == cps_api_oper_CREATE) {
        create = true;
    }

    /* Registering for VLAN object would also result in receving the
       port add/delete evetns. To distinguish it, need to check
       for tag/untag attribute
    */
    else if(op == cps_api_oper_DELETE){
        if(tag_attr != NULL or untag_attr != NULL){
            NAS_STG_LOG(INFO,"It is a port add/delete event");
            return true;
        }
    }
    else if(op == cps_api_oper_SET){
        return true;
    }

    hal_vlan_id_t vlan_id = (hal_ifindex_t)cps_api_object_attr_data_u32(vlan_attr);
    return (nas_stg_vlan_update(vlan_id,create,bridge_ifindex) != STD_ERR_OK) ? false: true;
}



bool nas_stg_process_phy_port_events(cps_api_object_t obj, void *param) {

    cps_api_operation_types_t op = cps_api_object_type_operation (cps_api_object_key (obj));

    if (op != cps_api_oper_CREATE) {
        return true;
    }

    cps_api_object_attr_t npu_attr = cps_api_object_attr_get(obj,BASE_IF_PHY_PHYSICAL_NPU_ID );
    cps_api_object_attr_t port_attr = cps_api_object_attr_get(obj,BASE_IF_PHY_PHYSICAL_PORT_ID);

    if (npu_attr == nullptr || port_attr == nullptr) {
        NAS_STG_LOG(ERR,"No npu/port passed to process phy port updates");
        return false;
    }

    npu_id_t npu = (npu_id_t)cps_api_object_attr_data_u32(npu_attr);
    port_t port  = (port_t)cps_api_object_attr_data_u32(port_attr);

    return (nas_stg_set_interface_default_state(npu,port) != STD_ERR_OK) ? false: true;
}


static t_std_error nas_stg_lag_register() {
    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_IF_LAG_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_stg_process_lag_events, NULL)!=cps_api_ret_code_OK) {
        NAS_STG_LOG(ERR,"Failed to register for LAG events updates");
        return STD_ERR(STG,FAIL,0);
    }

    return STD_ERR_OK;
}


static t_std_error nas_stg_vlan_register() {
    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_stg_process_vlan_events, NULL)!=cps_api_ret_code_OK) {
        NAS_STG_LOG(ERR,"Failed to register for VLAN events updates");
        return STD_ERR(STG,FAIL,0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_stg_phy_port_register() {
    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_IF_PHY_PHYSICAL_OBJ,
                                    cps_api_qualifier_TARGET);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_stg_process_phy_port_events, NULL)!=cps_api_ret_code_OK) {
        NAS_STG_LOG(ERR,"Failed to register for phy ports events updates");
        return STD_ERR(STG,FAIL,0);
    }

    return STD_ERR_OK;
}

static t_std_error cps_nas_stg_init(cps_api_operation_handle_t handle) {

    cps_api_return_code_t rc;
    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function = cps_nas_default_stg_get_function;
    f._write_function = cps_nas_default_stg_set_function;
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_STG_DEFAULT_STG_OBJ, cps_api_qualifier_TARGET)) {
        NAS_STG_LOG(ERR, "Could not translate %d to key %s",
                    (int)(BASE_STG_DEFAULT_STG_OBJ), cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(STG,FAIL,0);
    }
    if ((rc = cps_api_register(&f)) != cps_api_ret_code_OK) {
        return STD_ERR(STG,FAIL,rc);
    }

    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._read_function =  cps_nas_stg_get_function;
    f._write_function = cps_nas_stg_set_function;
    f._rollback_function = cps_nas_stg_rollback_function;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET)) {
        NAS_STG_LOG(ERR, "Could not translate %d to key %s",
                    (int)(BASE_STG_ENTRY_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(STG,FAIL,0);
    }

    if ((rc = cps_api_register(&f)) != cps_api_ret_code_OK) return STD_ERR(STG,FAIL,rc);

    memset(&f,0,sizeof(f));
    f.handle = handle;
    f._write_function = cps_nas_stg_vlan_set_function;

    memset(buff,0,sizeof(buff));
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_STG_ENTRY_VLAN,cps_api_qualifier_TARGET)) {
        NAS_STG_LOG(ERR, "Could not translate %d to key %s",
                    (int)(BASE_STG_ENTRY_VLAN),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(STG,FAIL,0);
    }

    if ((rc = cps_api_register(&f)) != cps_api_ret_code_OK) return STD_ERR(STG,FAIL,rc);
    return STD_ERR_OK;
}


t_std_error nas_stg_init(cps_api_operation_handle_t handle) {

    t_std_error rc = STD_ERR_OK;

    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    const unsigned int NUM_EVENTS=2;
    cps_api_key_t keys[NUM_EVENTS];

    cps_api_key_init(&keys[0],cps_api_qualifier_OBSERVED,(cps_api_object_category_types_t)
                                            cps_api_obj_CAT_BASE_STG,BASE_STG_ENTRY_OBJ,0);
    cps_api_key_init(&keys[1],cps_api_qualifier_TARGET,(cps_api_object_category_types_t)
                                            cps_api_obj_CAT_BASE_STG, BASE_STG_ENTRY_OBJ,0);

    reg.number_of_objects = NUM_EVENTS;
    reg.objects = keys;

    if (cps_api_event_thread_reg(&reg,nas_stg_event_function_cb,NULL)!=cps_api_ret_code_OK) {
        return STD_ERR(STG,FAIL,0);
    }

    if((rc = nas_stg_get_npu_list()) != STD_ERR_OK) return rc;

    if((rc = nas_stg_create_default_instance()) != STD_ERR_OK) return rc;

    if ((rc = cps_nas_stg_init(handle)) != STD_ERR_OK) return rc;

    if ((rc = nas_stg_lag_register()) != STD_ERR_OK) return rc;

    if ((rc = nas_stg_vlan_register()) != STD_ERR_OK) return rc;

    if ((rc = nas_stg_phy_port_register()) != STD_ERR_OK) return rc;

    return (rc);
}
