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
 * filename: nas_switch_log.h
 *
 */

#ifndef NAS_SWITCH_LOG_H_
#define NAS_SWITCH_LOG_H_

#include "std_error_codes.h"
#include "cps_api_operation.h"


/*
 * @brief initialize the nas switch logging
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error nas_switch_log_init(cps_api_operation_handle_t handle);


#endif /* NAS_SWITCH_LOG_H_ */
