/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mc_main.cpp
 */

#include "nas_mc_util.h"

t_std_error nas_mc_init(void)
{
    if (nas_mc_cps_init() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-MAIN", "Failed to initialize NAS Multicast CPS");
        return STD_ERR(MCAST, FAIL, 0);
    }
    if (nas_mc_proc_init() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-MAIN", "Failed to initialize NAS Multicast Proc");
        return STD_ERR(MCAST, FAIL, 0);
    }

    return STD_ERR_OK;
}
