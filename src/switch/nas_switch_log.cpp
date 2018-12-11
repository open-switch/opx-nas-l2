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
 * filename: nas_switch_log.cpp
 *
 */

#include "cps_api_operation.h"
#include "std_error_codes.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "dell-base-switch-element.h"
#include "nas_ndi_switch.h"
#include "event_log.h"
#include "nas_switch_log.h"

static cps_api_return_code_t cps_nas_switch_log_set_function(void * context,
                             cps_api_transaction_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        EV_LOGGING(SYSTEM,ERR,"NAS-DIAG","Invalid operation %d for setting switch log",op);
        return cps_api_ret_code_ERR;
    }

    BASE_SWITCH_SUBSYSTEM_t switch_system_id;
    cps_api_object_attr_t switch_system_id_attr;

    if ((switch_system_id_attr = cps_api_get_key_data(obj,BASE_SWITCH_SET_LOG_INPUT_SUBSYSTEM_ID)) == NULL) {
        EV_LOGGING(SYSTEM,ERR,"NAS-DIAG","No Module id passed for Updating sai log level");
        return cps_api_ret_code_ERR;
    }

    switch_system_id = (BASE_SWITCH_SUBSYSTEM_t) cps_api_object_attr_data_u32(switch_system_id_attr);
    cps_api_attr_id_t log_level_attr_id = BASE_SWITCH_SET_LOG_INPUT_LEVEL;
    cps_api_object_attr_t log_level_attr = cps_api_object_e_get (obj, &log_level_attr_id, 1);

    if(log_level_attr == NULL){
        EV_LOGGING(SYSTEM,ERR,"NAS-DIAG","No log level passed for Updating sai log level"
                            "for module %d",switch_system_id);
        return cps_api_ret_code_ERR;
    }

    BASE_SWITCH_LOG_LEVEL_t log_level = (BASE_SWITCH_LOG_LEVEL_t)
                                        cps_api_object_attr_data_u32(log_level_attr);
    t_std_error rc;
    if( (rc =ndi_switch_set_sai_log_level(switch_system_id,log_level)) != STD_ERR_OK ){
        EV_LOGGING(SYSTEM,ERR,"NAS-DIAG","Failed to set log_level to %d for sai module %d "
                "got the return code %d ",log_level,switch_system_id,rc);
        return cps_api_ret_code_ERR;
    }

    return cps_api_ret_code_OK;
}



t_std_error nas_switch_log_init(cps_api_operation_handle_t handle) {

    cps_api_return_code_t rc;
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));

    f.handle = handle;
    f._write_function = cps_nas_switch_log_set_function;

    char buff[CPS_API_KEY_STR_MAX];
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_SWITCH_SET_LOG_OBJ,cps_api_qualifier_TARGET)) {
        EV_LOGGING(SYSTEM,ERR,"NAS-DIAG","Could not translate %d to key %s",
               (int)(BASE_SWITCH_SET_LOG_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(DIAG,FAIL,0);
    }

    if ((rc = cps_api_register(&f)) != cps_api_ret_code_OK) return STD_ERR(DIAG,FAIL,rc);

    return STD_ERR_OK;
}
