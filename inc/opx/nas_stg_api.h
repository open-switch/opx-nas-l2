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
 * filename: nas_stg_api.h
 *
 */

#ifndef NAS_STG_API_H
#define NAS_STG_API_H

#include "dell-base-stg.h"
#include "event_log.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "ds_common_types.h"
#include "nas_switch.h"
#include "nas_ndi_stg.h"
#include "nas_base_utils.h"

#include <map>
#include <vector>
#include <utility>
#include <set>
#include <cstdbool>
#include <stdint.h>
#include <map>
#include <set>


#define NAS_STG_LOG(type, msg, ...)\
                       EV_LOGGING(NAS_L2,type,"NAS-STG",msg, ##__VA_ARGS__)

typedef unsigned int nas_stg_id_t;

/*
 * lag member port list and map to maintain lag and its member port
 */
typedef std::set <hal_ifindex_t> nas_lag_port_list_t;
typedef std::map <hal_ifindex_t, nas_lag_port_list_t> nas_stg_lag_map_t;
typedef std::pair <hal_ifindex_t, nas_lag_port_list_t> nas_stg_lag_pair;


/*
 * port list to be used for reading interface status of stg
 */
typedef std::set <hal_ifindex_t> nas_stg_port_list_t;

/*
 * vlan list to be used in the stg entry
 */
typedef std::set<hal_vlan_id_t> nas_stg_vlan_list_t;
typedef std::set<hal_vlan_id_t>::iterator nas_stg_vlan_list_it;


/*
 * Map to maintain list of npu id to stg id mapping
 */
typedef std::map<npu_id_t,ndi_stg_id_t> npu_to_stg_map_t;
typedef std::map<npu_id_t,ndi_stg_id_t>::iterator npu_to_stg_map_it;
typedef std::pair<npu_id_t,ndi_stg_id_t> npu_to_stg_map_pair;

typedef std::map<hal_ifindex_t,BASE_STG_INTERFACE_STATE_t> if_stp_map_t;
/*
 * NAS STG structure to maintain all information about STG Entry.
 */
typedef struct {
    nas_stg_id_t nas_stg_id;            //NAS generated id to be used a key
    npu_to_stg_map_t npu_to_stg_map;    //NPU Id to STG Id map
    nas_stg_vlan_list_t vlan_list;      //List of vlans associated with the STG
    nas_switch_id_t switch_id;          //Switch Id to which this entry belongs
    hal_ifindex_t bridge_index;         //Bridge Index if associated with STG
    nas::attr_set_t attrs;              //Attribute set to keep track of attributes
    bool cps_created;                    // Instance was created via CPS
    if_stp_map_t stp_states;
}nas_stg_entry_t;


/*
 * STG Entry table which contains all the STG entries with NAS generated id as a key
 */
typedef std::map < nas_stg_id_t , nas_stg_entry_t> nas_stg_table_t;
typedef std::map <nas_stg_id_t , nas_stg_entry_t >::iterator nas_stg_table_it;
typedef std::pair <nas_stg_id_t, nas_stg_entry_t > nas_stg_table_pair;


/*
 * Bridge to STG map which maintains bridge to STG mapping
 */
typedef std::map < hal_ifindex_t , nas_stg_id_t > nas_br_to_stg_map_t;
typedef std::map < hal_ifindex_t , nas_stg_id_t >::iterator nas_br_to_stg_map_it;
typedef std::pair< hal_ifindex_t , nas_stg_id_t > nas_br_to_stg_pair;


/*
 * Bridge to VLAN mapping which maintains vlans associated with the bridge
 */
typedef std::map < hal_ifindex_t , hal_vlan_id_t > nas_br_to_vlan_map_t;
typedef std::map < hal_ifindex_t , hal_vlan_id_t >::iterator nas_br_to_vlan_map_it;
typedef std::pair< hal_ifindex_t , hal_vlan_id_t > nas_br_to_vlan_pair;


/*
 * VLAN to STG map which maintains vlan associated with stg id
 */
typedef std::map < hal_vlan_id_t , nas_stg_id_t > nas_vlan_to_stg_map_t;
typedef std::pair< hal_vlan_id_t , nas_stg_id_t > nas_vlan_to_stg_pair_t;


/*
 * Set to maintain list of NPUs
 */
typedef std::set<npu_id_t> nas_stg_npu_ids;


/*
 * Map which maintains switch id to list of NPUs
 */
typedef std::map<nas_switch_id_t,nas_stg_npu_ids>nas_stg_switch_npu_map_t;
typedef std::pair<nas_switch_id_t,nas_stg_npu_ids>nas_stg_switch_npu_pair_t;


/*
 * Map which maintains switch id to default stg id
 */
typedef std::map<nas_switch_id_t,nas_stg_id_t>nas_stg_switch_defult_stg_map_t;
typedef std::pair<nas_switch_id_t,nas_stg_id_t>nas_stg_switch_defult_stg_map_pair_t;


/*
 * create the default STG instance
 */
t_std_error nas_stg_create_default_instance();

/*
 * Get the default STG instance
 */
t_std_error nas_stg_get_default_instance(cps_api_object_list_t list);


/*
 * Initialize the STG module
 */
t_std_error nas_stg_init(cps_api_operation_handle_t handle);


/*
 * Create new STG instance via CPS API
 */
t_std_error nas_stg_cps_create_instance (cps_api_object_t obj);


/*
 * Delete the existing STG instance via CPS API
 */
t_std_error nas_stg_cps_delete_instance (nas_stg_id_t stg_id);


/*
 * Update the existing STG instance via CPS API
 */
t_std_error nas_stg_set_instance(cps_api_object_t obj,nas_stg_id_t stg_id);


/*
 * Add vlan to the bridge to maintain bridge to vlan mapping
 */
t_std_error nas_stg_add_vlan_to_bridge (hal_ifindex_t bid, hal_vlan_id_t  vlan_id);


/*
 *  Delete the STG instance via cps-api-linux(netlink) notifications
 */
t_std_error nas_stg_delete_instance (hal_ifindex_t bid);


/*
 * Get all the STG instance inforation via CPS API
 */
t_std_error nas_stg_get_all_info(cps_api_object_list_t list);


/*
 * Get the specific instance info via CPS API
 */
t_std_error nas_stg_get_instance_info(cps_api_object_list_t list, nas_stg_id_t id,
                                      nas_stg_port_list_t* intf_list);


/*
 * Update the stp state of an interface via cps-api-linux(netlink) notification
 */
t_std_error nas_stg_update_stg_state(hal_ifindex_t bid, hal_ifindex_t intf_index, unsigned int state);


/*
 * Get the list of npus and switch ids in a system
 */
t_std_error nas_stg_get_npu_list(void);


/*
 * Add/Delete Specific vlans to/from stg instance
 */
t_std_error nas_stg_update_vlans(cps_api_object_t obj,nas_stg_id_t id, bool add);

/*
 * Process Base LAG updates
 */
t_std_error nas_stg_lag_update(hal_ifindex_t lag_index, cps_api_object_t obj);

/*
 * Process Base VLAN updates
 */
t_std_error nas_stg_vlan_update(hal_vlan_id_t id,bool add,hal_ifindex_t bridge_index);

t_std_error nas_stg_set_default_instance_state(cps_api_object_t obj);

t_std_error nas_stg_set_interface_default_state(npu_id_t npu,port_t port);

#endif /* NAS_STG_API_H */
