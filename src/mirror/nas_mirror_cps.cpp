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
 * filename: nas_mirror_cps.cpp
 */


#include "nas_mirror_api.h"
#include "cps_api_events.h"
#include "cps_api_key.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

#include "event_log_types.h"
#include "event_log.h"

#include <stdlib.h>


cps_api_return_code_t cps_nas_mirror_get_function (void * context, cps_api_get_params_t * param, size_t ix) {

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    cps_api_object_attr_t mirror_id_attr = cps_api_get_key_data(filt,BASE_MIRROR_ENTRY_ID);
    t_std_error rc;

    if (mirror_id_attr == NULL) {
         if((rc = nas_mirror_get_all_info(param->list)) != STD_ERR_OK){
             return (cps_api_return_code_t)rc;
         }
     }
     else{
         nas_mirror_id_t mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);
         if((rc = nas_mirror_get_session_info(param->list,mirror_id)) != STD_ERR_OK){
             return (cps_api_return_code_t)rc;
         }
    }

    return cps_api_ret_code_OK;
}


cps_api_return_code_t cps_nas_mirror_set_function(void * context, cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_mirror_id_t mirror_id = 0;
    t_std_error rc;

    if( op == cps_api_oper_CREATE){

        if(( rc = nas_mirror_create_session(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }

        cps_api_object_t cloned = cps_api_object_create();
        bool obj_rc = true;
        if (cloned!=NULL && cps_api_object_clone(cloned,obj)) {
            obj_rc = cps_api_object_list_append(param->prev,cloned);
        }
        if (!obj_rc) {
            if (cloned) cps_api_object_delete(cloned);
            return (cps_api_return_code_t)STD_ERR(MIRROR,NOMEM,0);
        }

    }

    if( op == cps_api_oper_SET || op == cps_api_oper_DELETE) {
        cps_api_object_attr_t mirror_id_attr;
        if ((mirror_id_attr = cps_api_get_key_data(obj,BASE_MIRROR_ENTRY_ID)) == NULL) {
            NAS_MIRROR_LOG(ERR,"No Mirror id passed for Updating/deleting Mirror session");
            return (cps_api_return_code_t)STD_ERR(MIRROR,CFG,0);
        }

        mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);

        if((rc = nas_mirror_get_session_info(param->prev,mirror_id)) != cps_api_ret_code_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE) {
        if((rc = nas_mirror_delete_session(obj,mirror_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_mirror_set_session(obj,mirror_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}

cps_api_return_code_t cps_nas_mirror_rollback_function (void * context, cps_api_transaction_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_get(param->prev,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_mirror_id_t mirror_id = 0;
    t_std_error rc;

    if( op == cps_api_oper_SET || op == cps_api_oper_CREATE) {

        cps_api_object_attr_t mirror_id_attr;
        if ((mirror_id_attr = cps_api_get_key_data(obj,BASE_MIRROR_ENTRY_ID)) == NULL) {
            NAS_MIRROR_LOG(ERR,"No Mirror id passed for Updating/deleting Mirror session");
            return (cps_api_return_code_t)STD_ERR(MIRROR,CFG,0);
        }

        mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);
   }

    if( op == cps_api_oper_CREATE){
        if((rc = nas_mirror_delete_session(obj,mirror_id)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_DELETE){
        if((rc = nas_mirror_create_session(obj)) != STD_ERR_OK){
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        if((rc = nas_mirror_set_session(obj,mirror_id)) != STD_ERR_OK){
             return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}


t_std_error nas_mirroring_init(cps_api_operation_handle_t handle ) {

    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));
    f.handle = handle;

    f._read_function =  cps_nas_mirror_get_function;
    f._write_function = cps_nas_mirror_set_function;
    f._rollback_function = cps_nas_mirror_rollback_function;

    char buff[CPS_API_KEY_STR_MAX];
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_MIRROR_ENTRY_OBJ,cps_api_qualifier_TARGET)) {
        NAS_MIRROR_LOG(ERR,"Could not translate %d to key %s",
                                (int)(BASE_MIRROR_ENTRY_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(MIRROR,FAIL,0);
    }

    cps_api_return_code_t rc = cps_api_register(&f);
    return STD_ERR_OK_IF_TRUE(rc==cps_api_ret_code_OK,STD_ERR(MIRROR,FAIL,rc));
}
