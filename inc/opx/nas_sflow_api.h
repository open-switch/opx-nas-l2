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
 * filename: nas_sflow_api.h
 *
 */


#ifndef NAS_SFLOW_API_H
#define NAS_SFLOW_API_H

#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "event_log.h"
#include "nas_ndi_sflow.h"
#include "ds_common_types.h"
#include "nas_base_utils.h"

#include <unordered_map>
#include <vector>
#include <utility>

#define NAS_SFLOW_LOG(type, msg, ...)\
                       EV_LOGGING(NAS_L2,type,"NAS-SFLOW",msg, ##__VA_ARGS__)

typedef unsigned int nas_sflow_id_t;

/*
 * structure which maintains the sflow entries
 */
typedef struct {
    hal_ifindex_t ifindex;              //ifindex on which sampling needs to be enabled
    nas_sflow_id_t nas_sflow_id;        //nas generated sflow id
    ndi_sflow_entry_t ndi_sflow_entry;  // NDI Sflow entry
    nas::attr_set_t attr_set;           //attribute set to keep track of which
                                        //attributes are set
}nas_sflow_entry_t;


/*
 * NAS Sflow entry map which is indexed by nas sflow id
 */
typedef std::unordered_map<nas_sflow_id_t, nas_sflow_entry_t > nas_sflow_map_t;
typedef std::pair<nas_sflow_id_t, nas_sflow_entry_t > nas_sflow_pair;
typedef std::unordered_map<nas_sflow_id_t, nas_sflow_entry_t >::iterator nas_sflow_map_it;


/*
 * Initialize the NAS sFlow module
 */
t_std_error nas_sflow_init(cps_api_operation_handle_t handle);


/*
 * Create new NAS sFlow session
 */
t_std_error nas_sflow_create_session(cps_api_object_t obj);


/*
 * Delete existing sFlow session
 */
t_std_error nas_sflow_delete_session(nas_sflow_id_t);


/*
 * Update existing sFlow session
 */
t_std_error nas_sflow_update_session(cps_api_object_t obj,nas_sflow_id_t id);


/*
 * Get all NAS sFlow session information
 */
t_std_error nas_sflow_get_all_info(cps_api_object_list_t list);


/*
 * Get specific NAS sFlow session information
 */
t_std_error nas_sflow_get_session_info(cps_api_object_list_t list,nas_sflow_id_t id);


#endif /* NAS_SFLOW_API_H */
