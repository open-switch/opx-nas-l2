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
 * filename: nas_switch_mac.cpp
 *
 */

#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_object_category.h"
#include "dell-base-pas.h"
#include "dell-base-switch-element.h"
#include "nas_ndi_switch.h"
#include "cps_class_map.h"
#include "ds_common_types.h"
#include "nas_switch.h"
#include "event_log.h"

#include <string.h>
#include <unistd.h>

static hal_mac_addr_t sys_mac_base = {0,0,0,0,0,0};

t_std_error nas_switch_mac_get(hal_mac_addr_t *mac_base)
{
    memcpy(*mac_base, sys_mac_base, sizeof(sys_mac_base));
    return(STD_ERR_OK);
}

t_std_error nas_switch_mac_init(cps_api_operation_handle_t handle) {
     while(1) {
        if (nas_get_platform_base_mac_address(&sys_mac_base) == STD_ERR_OK)  {
            break;
        }
        EV_LOGGING(SYSTEM, DEBUG, "PLATFORM", "waiting for base mac address from PAS");
        sleep(1);
    }

    EV_LOGGING(SYSTEM, DEBUG, "PLATFORM", "Base MAC address %02x:%02x:%02x:%02x:%02x:%02x",
                           sys_mac_base[0], sys_mac_base[1], sys_mac_base[2], sys_mac_base[3],
                                     sys_mac_base[4], sys_mac_base[5]);
    npu_id_t npu =0; // TODO
    nas_ndi_switch_param_t param;
    (void)nas_switch_mac_get(&param.mac);

    return(ndi_switch_set_attribute(npu, BASE_SWITCH_SWITCHING_ENTITIES_SWITCHING_ENTITY_DEFAULT_MAC_ADDRESS, &param));
}
