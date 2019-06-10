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
 * filename: nas_l2.cpp
 */


#include "nas_l2_init.h"
#include "nas_switch_mac.h"
#include "nas_mirror_api.h"
#include "cps_api_operation.h"
#include "nas_sflow_api.h"
#include "nas_stg_api.h"
#include "nas_mac_api.h"
#include "nas_hash_cps.h"
#include "nas_switch_cps.h"
#include "nas_switch_log.h"

#define NUM_L2_CPS_API_THREAD 1

static cps_api_operation_handle_t handle;
static cps_api_operation_handle_t stp_handle;
static cps_api_operation_handle_t mac_handle;

t_std_error (*nas_l2_init_functions[])(cps_api_operation_handle_t handle) = {
        nas_switch_mac_init,
        nas_mirroring_init,
        nas_sflow_init,
        nas_hash_init,
        nas_switch_cps_init,
        nas_switch_log_init,
};

t_std_error nas_l2_init(void) {

    if (cps_api_operation_subsystem_init(&handle,NUM_L2_CPS_API_THREAD)!=cps_api_ret_code_OK) {
        return STD_ERR(CPSNAS,FAIL,0);
    }

    if (cps_api_operation_subsystem_init(&stp_handle,NUM_L2_CPS_API_THREAD)!=cps_api_ret_code_OK) {
        return STD_ERR(CPSNAS,FAIL,0);
    }

    if (cps_api_operation_subsystem_init(&mac_handle,NUM_L2_CPS_API_THREAD)!=cps_api_ret_code_OK) {
        return STD_ERR(CPSNAS,FAIL,0);
    }

    t_std_error rc;
    size_t ix = 0;
    size_t mx = sizeof(nas_l2_init_functions)/sizeof(*nas_l2_init_functions);
    for ( ; ix < mx ; ++ix ) {
        rc = nas_l2_init_functions[ix](handle);
        if (rc!=STD_ERR_OK) return rc;
    }

    if((rc = nas_stg_init(stp_handle)) != STD_ERR_OK){
        return rc;
    }

    if((rc = nas_mac_init(mac_handle)) != STD_ERR_OK){
        return rc;
    }

    return STD_ERR_OK;
}
