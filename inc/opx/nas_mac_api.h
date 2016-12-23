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
 * filename: nas_mac_api.h
 *
 */

#ifndef NAS_MAC_API_H
#define NAS_MAC_API_H

#include "dell-base-l2-mac.h"
#include "event_log.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "ds_common_types.h"
#include "nas_switch.h"
#include "std_mac_utils.h"
#include "nas_ndi_mac.h"
#include "std_mutex_lock.h"
#include "std_condition_variable.h"

#include <unordered_map>
#include <queue>

#define NAS_MAC_LOG(type, msg, ...)\
                    EV_LOGGING( L2MAC,type, "", msg, ##__VA_ARGS__)

#define SWITCH_DEFAULT_MAC_AGE_TIMEOUT 1800

typedef enum del_filter_type_ {
    DEL_VLAN_FILTER,
    DEL_MAC_FILTER,
    DEL_IF_FILTER
} del_filter_type_t;

struct nas_mac_entry_key {

    hal_vlan_id_t  vlan_id;
    hal_mac_addr_t mac_addr;

    bool operator== (const nas_mac_entry_key& rhs)  const
    {
        if (vlan_id != rhs.vlan_id) return false;
        if (memcmp(mac_addr, rhs.mac_addr, HAL_MAC_ADDR_LEN)) return false;
        return true;
    }
};

typedef struct {
    nas_mac_entry_key           entry_key;
    hal_ifindex_t               ifindex;
    BASE_MAC_PACKET_ACTION_t    pkt_action;
    npu_id_t                    learned_from_npu;
    bool                         npu_configured=true;
    bool                         os_configured=false;
}nas_mac_entry_t;

class mac_entry_hash
{
public:
    std::size_t operator() (nas_mac_entry_key const&s) const
    {
        static const size_t MAC_STR_BUFF=20;
        char mac_str[MAC_STR_BUFF] = {0};
        std::string mac_text = std_mac_to_string(&s.mac_addr, &mac_str[0], sizeof(mac_str));
        std::size_t mac_hash = std::hash<std::string>() (mac_text);
        std::size_t vlan_hash = std::hash<unsigned int>() (s.vlan_id);
        return mac_hash ^ (vlan_hash << 1);
    }
};

class nas_mac_table_info {

public:
    typedef std::unordered_map<nas_mac_entry_key, nas_mac_entry_t, mac_entry_hash> nas_mac_entry_map_t;
    typedef nas_mac_entry_map_t::iterator nas_mac_entry_map_it;
    inline bool get_mac_table_by_type(nas_mac_entry_map_t **mac_type_table, bool type_static);

    bool add_mac_entry(const nas_mac_entry_t &entry, bool type_static);

    bool get_mac_entry_details (const nas_mac_entry_key &key_pair, nas_mac_entry_t *entry, bool type_static);

    bool delete_mac_entry (const nas_mac_entry_key &key_pair, bool type_static, bool flush_all);

    bool is_mac_entry_present (const nas_mac_entry_key &key_pair, bool type_static);

    bool print_table (bool type_static);

    std::size_t static_entry_count () {
        return static_mac_map.size();
    }

    std::size_t dynamic_entry_count () {
        return dynamic_mac_map.size();
    }

    void set_mac_age_timeout (unsigned int timeout) {
        mac_age_timer_val = timeout;
    }

    unsigned int get_mac_age_timeout (void) {
        return mac_age_timer_val;
    }

private:
    nas_mac_entry_map_t         static_mac_map;
    nas_mac_entry_map_t         dynamic_mac_map;
    uint32_t                    mac_age_timer_val = 0;
};

typedef enum{
    NAS_MAC_ADD=0,
    NAS_MAC_DEL
}nas_l2_mac_op_t;

typedef struct {
    nas_mac_entry_t entry;
    ndi_mac_delete_type_t del_type;
    nas_l2_mac_op_t op_type;
    bool static_type;
    bool subtype_all;

}nas_mac_request_entry_t;

typedef std::queue<nas_mac_request_entry_t> nas_mac_request_queue_t;

t_std_error nas_mac_init(cps_api_operation_handle_t handle);

t_std_error nas_mac_cps_create_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_delete_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_update_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_find_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_flush_entry(cps_api_object_t obj);

t_std_error nas_mac_set_entry(cps_api_object_t obj,nas_mac_entry_t *entry);

t_std_error nas_mac_create_entry(nas_mac_entry_t *entry, bool static_type, bool event_type);

t_std_error nas_mac_delete_entry(nas_mac_entry_t *entry, bool static_type, bool type_set, bool event_type);

t_std_error nas_mac_update_entry(nas_mac_entry_t *entry, bool static_type, bool event_type);

t_std_error nas_mac_get_all_info(cps_api_object_list_t list, bool static_type);

t_std_error nas_mac_flush_vlan_entries_of_port(uint32_t vlan, hal_ifindex_t port_index);

/* fetch all macs for a given vlan */
t_std_error nas_mac_get_all_vlan_info(cps_api_object_list_t list, uint16_t vlan_id, bool static_type);

/* fetch all macs entries for a given if index */
t_std_error nas_mac_get_all_if_info(cps_api_object_list_t list, hal_ifindex_t if_index, bool static_type);

/* fetch the count of mac addresses with various filters */
t_std_error nas_mac_get_consolidated_count(cps_api_object_list_t list, uint16_t vlan_id, hal_ifindex_t if_index,
                                           bool static_type, bool static_type_set);

/* fetch the entire mac table */
t_std_error nas_mac_get_all_mac_info(cps_api_object_list_t list, hal_mac_addr_t mac_addr, bool static_type);


t_std_error nas_mac_handle_if_down(hal_ifindex_t ifindex);

/* consumer thread which dequeues the mac operation requests */
void nas_l2_mac_req_handler(void);

t_std_error nas_mac_lag_obj_id_get (hal_ifindex_t if_index, ndi_obj_id_t& obj_id);

/* Delete the mac entry from hw */
t_std_error nas_mac_delete_entries_from_hw(nas_mac_entry_t *entry, bool static_type, ndi_mac_delete_type_t del_type,
                                                  bool subtype_all);

/* get the hw mac operations queue */
nas_mac_request_queue_t & nas_mac_get_request_queue(void);

/* get the mutex for the hw mac operation queue */
std_mutex_type_t * nas_mac_get_request_mutex(void);

/* get the condition variable for hw mac request queue */
std_condition_var_t * nas_mac_get_request_cv(void);

/* Initialize the event thread handle */
t_std_error nas_mac_event_handle_init();

/* Publish the MAC object */
t_std_error nas_mac_event_publish(cps_api_object_t obj);

/* Create CPS object from MAC entry */
t_std_error nas_mac_publish_entry(nas_mac_entry_t *entry,bool is_static,bool flush_all,cps_api_operation_types_t op);

#endif /* NAS_MAC_API_H */
