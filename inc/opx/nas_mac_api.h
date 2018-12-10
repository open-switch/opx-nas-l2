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
#include "nas_base_utils.h"
#include "std_ip_utils.h"

#include <unordered_map>
#include <list>
#include <unordered_set>
#include <string>

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

struct nas_mac_entry_t {
    nas_mac_entry_key           entry_key = {0};
    hal_ifindex_t               ifindex=0;
    hal_ifindex_t               bridge_ifindex=0;
    ndi_obj_id_t                bridge_id=0;
    hal_ip_addr_t               endpoint_ip={0};
    ndi_mac_entry_type_t        entry_type;
    ndi_obj_id_t                endpoint_ip_id;
    BASE_MAC_PACKET_ACTION_t    pkt_action;
    npu_id_t                    learned_from_npu;
    bool                        npu_configured=true;
    bool                        os_configured=false;
    bool                        is_static = false;
    bool                        publish=false;
    bool                        cache=false;
};

typedef enum{
    NAS_MAC_ADD=0,
    NAS_MAC_DEL,
    NAS_MAC_FLUSH,
    NAS_MAC_MOVE
}nas_l2_mac_op_t;

typedef enum{
    NAS_MAC_NPU_EVENT=0,
    NAS_MAC_CPS_EVENT
}nas_l2_mac_event_t;

typedef struct{
    nas_l2_mac_event_t ev_type;
    size_t len;
}nas_l2_event_header_t;

typedef struct {
    nas_mac_entry_t entry;
    ndi_mac_delete_type_t del_type;
    nas_l2_mac_op_t op_type;
    bool static_type;
}nas_mac_cps_event_t;

typedef struct{
    nas_l2_mac_op_t op_type;
    nas_mac_entry_t entry;
}nas_mac_npu_event_t;

typedef struct vni_rem_ip{
    std::string ip;
    hal_ifindex_t br_index;

    bool operator== (const vni_rem_ip & rhs)  const
    {
        if (br_index != rhs.br_index) return false;
        if(ip != rhs.ip) return false;
        return true;
    };


    bool operator <(const vni_rem_ip & rhs) const
    {
        return (br_index < rhs.br_index )||
                ((br_index == rhs.br_index) && (ip< rhs.ip));

    };

    vni_rem_ip(hal_ip_addr_t &rip, hal_ifindex_t rbr_index){
        br_index = rbr_index;
        char buff[HAL_INET6_TEXT_LEN + 1];
        if(std_ip_to_string(&rip,buff,HAL_INET6_TEXT_LEN)){
            ip = std::string(buff);
        }
    }
}vni_rem_ip_t;

typedef std::list<nas_mac_npu_event_t> nas_mac_npu_event_queue_t;

typedef std::list<nas_mac_cps_event_t> nas_mac_cps_event_queue_t;

t_std_error nas_mac_init(cps_api_operation_handle_t handle);

t_std_error nas_mac_cps_create_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_delete_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_update_entry(cps_api_object_t obj);

t_std_error nas_mac_cps_flush_entry(cps_api_object_t obj);

t_std_error nas_mac_clear_hw_mac(nas_mac_cps_event_t & req_entry);

t_std_error nas_mac_flush_vlan_entries_of_port(uint32_t vlan, hal_ifindex_t port_index);

t_std_error nas_mac_handle_if_down(hal_ifindex_t ifindex);

/* consumer thread which dequeues the mac operation requests */
void nas_l2_mac_npu_req_handler(void);

void nas_l2_mac_cps_req_handler(void);

/* Delete the mac entry from hw */
t_std_error nas_mac_delete_entries_from_hw(nas_mac_entry_t *entry,ndi_mac_delete_type_t del_type);

/* Initialize the event thread handle */
t_std_error nas_mac_event_handle_init();

/* Publish the MAC object */
t_std_error nas_mac_event_publish(cps_api_object_t obj);

/* Create CPS object from MAC entry */
t_std_error nas_mac_publish_entry(nas_mac_entry_t *entry,bool is_static,bool flush_all,cps_api_operation_types_t op);

void nas_mac_create_entry_from_cb(nas_mac_entry_t & entry, bool add);

t_std_error nas_mac_send_cps_event_notification(void * data, int len);

t_std_error nas_mac_send_npu_event_notification(void * data, int len);

void nas_mac_event_notification_cb(npu_id_t npu_id, ndi_mac_event_type_t ev_type, ndi_mac_entry_t *mac_entry, bool is_lag_index);

bool nas_get_mac_entry_from_ndi(nas_mac_entry_t & entry);

t_std_error nas_mac_update_entry_in_os(nas_mac_entry_t *entry,cps_api_operation_types_t op);

void nas_mac_flush_count_dump(void);

bool nas_mac_publish_flush_event(ndi_mac_delete_type_t del_type, nas_mac_entry_t * entry);

bool nas_mac_process_os_event(nas_mac_entry_t & entry, nas::attr_set_t & attr,cps_api_operation_types_t op);

bool _process_remote_endpint(const char * vtep_name, hal_ip_addr_t & ip_addr, ndi_obj_id_t tunnel_id,bool add);

bool _get_endpoint_tunnel_id(vni_rem_ip_t & _rem_ip, ndi_obj_id_t & obj_id);

bool nas_mac_get_vtep_name_from_tunnel_id(ndi_obj_id_t id, std::string & s);

bool _process_bridge_event(const char * br_name, const char * vtep_name, bool add);

bool nas_mac_update_remote_macs_cache(nas_mac_entry_t & entry,bool add);

int nas_mac_get_read_cps_thread_fd();

int nas_mac_get_write_cps_thread_fd();

int nas_mac_get_read_npu_thread_fd();

int nas_mac_get_write_npu_thread_fd();

bool nas_mac_get_1d_br_untag_vid(hal_ifindex_t ifx, hal_vlan_id_t &vlan_id);

void nas_mac_log_entry(nas_mac_entry_t *entry);

#endif /* NAS_MAC_API_H */
