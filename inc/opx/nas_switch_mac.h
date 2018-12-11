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
 * filename: nas_switch_mac.h
 *
 */

#ifndef NAS_SWITCH_MAC_H_
#define NAS_SWITCH_MAC_H_

#include "cps_api_operation.h"
#include "std_error_codes.h"


t_std_error nas_switch_mac_init(cps_api_operation_handle_t handle);

t_std_error nas_switch_mac_get(hal_mac_addr_t *mac_base);

#endif /* NAS_SWITCH_MAC_H_ */
