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
 * filename: nas_sflow_main.cpp
 */


#include "nas_sflow_api.h"
#include "cps_api_events.h"
#include "std_error_codes.h"

#include "nas_l2_init.h"
#include "dell-base-sflow.h"
#include "nas_sflow_api.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

static cps_api_return_code_t cps_nas_sflow_get_function (void * context, cps_api_get_params_t * param, size_t ix) {

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    cps_api_object_attr_t sflow_id_attr = cps_api_get_key_data(filt,BASE_SFLOW_ENTRY_ID);
    t_std_error rc;

    if (sflow_id_attr == NULL) {
        if((rc = nas_sflow_get_all_info(param->list)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
     }
     else{
         nas_sflow_id_t nas_sflow_id = cps_api_object_attr_data_u32(sflow_id_attr);
         if((rc = nas_sflow_get_session_info(param->list,nas_sflow_id)) != STD_ERR_OK ){
             return (cps_api_return_code_t)rc;
         }
    }

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t cps_nas_sflow_set_function(void * context,
                       cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_sflow_id_t sflow_entry_id = 0;
    t_std_error rc;

    if( op == cps_api_oper_CREATE){
        if((rc = nas_sflow_create_session(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_CREATE ) {
        cps_api_object_t cloned = cps_api_object_create();
        if(cloned == NULL){
            NAS_SFLOW_LOG(ERR,"failed to create new cps object");
            return (cps_api_return_code_t)STD_ERR(SFLOW,NOMEM,0);
        }
        cps_api_object_clone(cloned,obj);
        cps_api_object_list_append(param->prev,cloned);
    }

    if(op == cps_api_oper_DELETE || op == cps_api_oper_SET ){
        cps_api_object_attr_t sflow_id_attr;
        if ((sflow_id_attr = cps_api_get_key_data(obj,BASE_SFLOW_ENTRY_ID)) == NULL) {
            NAS_SFLOW_LOG(ERR,"No sFlow id passed for Updating/Deleting sFlow session");
            return (cps_api_return_code_t)STD_ERR(SFLOW,CFG,0);
        }

        sflow_entry_id = cps_api_object_attr_data_u32(sflow_id_attr);

        if((rc = nas_sflow_get_session_info(param->prev,sflow_entry_id)) != cps_api_ret_code_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE){
        if((rc = nas_sflow_delete_session(sflow_entry_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_sflow_update_session(obj,sflow_entry_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }
    return cps_api_ret_code_OK;
}


static cps_api_return_code_t cps_nas_sflow_rollback_function (void * context, cps_api_transaction_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_get(param->prev,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    unsigned int sflow_entry_id = 0 ;
    t_std_error rc;

    if(op == cps_api_oper_CREATE || op == cps_api_oper_SET ){
        cps_api_object_attr_t sflow_id_attr;
        if ((sflow_id_attr = cps_api_get_key_data(obj,BASE_SFLOW_ENTRY_ID)) == NULL) {
            NAS_SFLOW_LOG(ERR,"No sFlow id passed for Updating/Creating sFlow session");
            return (cps_api_return_code_t)STD_ERR(SFLOW,CFG,0);
        }

        sflow_entry_id = cps_api_object_attr_data_u32(sflow_id_attr);
    }

    if( op == cps_api_oper_CREATE){
        if((rc = nas_sflow_delete_session(sflow_entry_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE){
        if((rc = nas_sflow_create_session(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_sflow_update_session(obj,sflow_entry_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}

t_std_error nas_sflow_init(cps_api_operation_handle_t handle) {
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));

    f.handle = handle;
    f._read_function =  cps_nas_sflow_get_function;
    f._write_function = cps_nas_sflow_set_function;
    f._rollback_function = cps_nas_sflow_rollback_function;

    char buff[CPS_API_KEY_STR_MAX];
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_SFLOW_ENTRY_OBJ,cps_api_qualifier_TARGET)) {
        NAS_SFLOW_LOG(ERR,"Could not translate %d to key %s",(int)(BASE_SFLOW_ENTRY_OBJ),
                      cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(SFLOW,FAIL,0);
    }

    cps_api_return_code_t rc = cps_api_register(&f);

    return STD_ERR_OK_IF_TRUE(rc==cps_api_ret_code_OK,STD_ERR(SFLOW,FAIL,rc));
}
