/*
 * Copyright (c) 2017 Dell Inc.
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
 * filename: nas_mc_proc.cpp
 */


#include "cps_api_object.h"
#include "nas_mc_util.h"
#include "nas_types.h"
#include "std_thread_tools.h"
#include "std_ip_utils.h"
#include "nas_ndi_common.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mcast.h"
#include "nas_ndi_l2mc.h"
#include "nas_ndi_vlan.h"
#include "event_log.h"
#include "nas_switch.h"

#include <vector>
#include <set>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <inttypes.h>
#include <sstream>

#define TAG_PRINT_BUF_LEN   256

/**
 * Data structure related to message decoded from
 * event and used by main thread for configuring
 * multicast router port and route entry
 **/

/* Multicast snooping message type */
enum class mc_msg_type_t
{
    // Multicast router update
    MROUTER,
    // Multicast route entry update
    ROUTE,
    // Interface update
    INTERFACE
};

/* Multicast snooping operation type */
enum class mc_oper_type_t
{
    // Add mrouter or route entry
    ADD,
    // Delete mrouter or route entry
    DELETE,
    // Change enable/disable status of multicast snooping
    STATUS
};

const hal_ifindex_t ALL_INTERFACES = static_cast<hal_ifindex_t>(-1);

static const char* get_oper_type_name(mc_oper_type_t oper_type)
{
    switch(oper_type) {
    case mc_oper_type_t::ADD:
        return "ADD";
    case mc_oper_type_t::DELETE:
        return "DELETE";
    case mc_oper_type_t::STATUS:
        return "STATUS";
    }
    return "";
}

static const char* get_msg_type_name(mc_msg_type_t msg_type)
{
    switch(msg_type) {
    case mc_msg_type_t::MROUTER:
        return "Multicast Router Interface";
    case mc_msg_type_t::ROUTE:
        return "Group Attached Interface";
    case mc_msg_type_t::INTERFACE:
        return "Physical Interface";
    }
    return "";
}

struct mc_entry_key_t
{
    hal_ip_addr_t dst_ip;
    bool is_xg;
    hal_ip_addr_t src_ip;
};

struct _ip_addr_key_hash
{
    size_t operator()(const hal_ip_addr_t& key) const {
        size_t hash = std::hash<unsigned int>()(key.af_index);
        if (key.af_index == HAL_INET4_FAMILY) {
            hash ^= (std::hash<unsigned int>()(key.u.ipv4.s_addr) << 1);
        } else {
            for (int idx = 0; idx < HAL_INET6_LEN; idx ++) {
                hash ^= (std::hash<unsigned char>()(key.u.ipv6.s6_addr[idx]) << (idx + 1));
            }
        }
        return hash;
    }
};

struct _mc_entry_key_hash
{
    size_t operator()(const mc_entry_key_t& key) const {
        size_t hash = _ip_addr_key_hash()(key.dst_ip);
        hash ^= (std::hash<bool>()(key.is_xg) << 1);
        if (!key.is_xg) {
            hash ^= (_ip_addr_key_hash()(key.src_ip) << 1);
        }
        return hash;
    }
};

struct _ip_addr_key_equal
{
    bool operator()(const hal_ip_addr_t& k1, const hal_ip_addr_t& k2) const
    {
        if (k1.af_index != k2.af_index) {
            return false;
        }
        if (k1.af_index == HAL_INET4_FAMILY) {
            return k1.u.ipv4.s_addr == k2.u.ipv4.s_addr;
        } else {
            return memcmp(k1.u.ipv6.s6_addr, k2.u.ipv6.s6_addr, HAL_INET6_LEN) == 0;
        }
    }
};

struct _mc_entry_key_equal
{
    bool operator()(const mc_entry_key_t& k1, const mc_entry_key_t& k2) const
    {
        if (!_ip_addr_key_equal()(k1.dst_ip, k2.dst_ip)) {
            return false;
        }
        if (k1.is_xg != k2.is_xg) {
            return false;
        }
        if (!k1.is_xg) {
            return _ip_addr_key_equal()(k1.src_ip, k2.src_ip);
        }

        return true;
    }
};

static inline bool _is_af_match_ip_type(uint32_t af_index, mc_event_type_t ip_type)
{
    return ((af_index == HAL_INET4_FAMILY && ip_type == mc_event_type_t::IGMP) ||
            (af_index == HAL_INET6_FAMILY && ip_type == mc_event_type_t::MLD) ||
            (ip_type == mc_event_type_t::IGMP_MLD));
}

static char mc_ip_buf[HAL_INET6_TEXT_LEN + 1];

static const char *nas_mc_ip_to_string(const hal_ip_addr_t& ip_addr)
{
    const char* ip_str = std_ip_to_string(&ip_addr, mc_ip_buf, sizeof(mc_ip_buf));
    if (ip_str == nullptr) {
        ip_str = "";
    }
    return ip_str;
}

/* Multicast snooping message */
struct mc_snooping_msg_t
{
    // Request event type
    mc_event_type_t req_type;
    // VLAN ID
    hal_vlan_id_t vlan_id;
    // Operation type
    mc_oper_type_t oper_type;
    // For operation type STATUS, indicate if multicast snooping is enabled
    bool enable;
    // Message type
    mc_msg_type_t msg_type;
    // Specify
    bool have_ifindex;
    // Specify interface mapped to mrouter port or multicast host port
    hal_ifindex_t ifindex;
    // For interface cleanup, apply for all VLANs
    bool all_vlan;
    // For message type ROUTE, specify multicast group address
    hal_ip_addr_t group_addr;
    // For message type ROUTE, specify if it is (*,G) or (S, G)
    bool xg_entry;
    // For message type ROUTE, if it is (S, G) entry, specify group source address
    hal_ip_addr_t source_addr;

    /* HW related information for message type MROUTER */

    // List of multicast groups that need to be updated with mrouter interface
    std::unordered_map<mc_entry_key_t, std::tuple<ndi_obj_id_t, bool, bool, ndi_obj_id_t>,
                       _mc_entry_key_hash, _mc_entry_key_equal>
                mrouter_member_list;

    /* HW related information for message type ROUTE */

    // Whether specified multicast entry was created in NPU
    bool entry_exist;
    // NDI ID of multicast group, effective if entry_exist is TRUE
    ndi_obj_id_t group_id;
    // Whether multicast group member also in mrouter list
    bool member_is_mrouter;
    // Multicast group member ID
    ndi_obj_id_t member_id;
    // Is specified group member the last host member, used for member delete
    bool last_host_member;
    // List of all members created for mrouter interfaces
    std::unordered_map<hal_ifindex_t, ndi_obj_id_t> router_member_list;

    std::string dump_msg_info(bool is_sync);
};

std::string mc_snooping_msg_t::dump_msg_info(bool is_sync)
{
    std::ostringstream ss;
    ss << "-------------------------------" << std::endl;
    ss << "Received Multicast Message" << std::endl;
    ss << "-------------------------------" << std::endl;
    ss << "  Task Type      : " << (is_sync ? "SYNC" : "NON-SYNC") << std::endl;
    ss << "  Event Type     : " <<
                     (req_type == mc_event_type_t::IGMP_MLD ? "IGMP_MLD" :
                      (req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"))
                     << std::endl;
    if (all_vlan) {
        ss << "  VLAN ID        : All" << std::endl;
    } else {
        ss << "  VLAN ID        : " << vlan_id << std::endl;
    }
    ss << "  Operation Type : " <<
                     get_oper_type_name(oper_type) << std::endl;
    if (oper_type == mc_oper_type_t::STATUS) {
        ss << "  Enable         : " <<
                         (enable ? "TRUE" : "FALSE") << std::endl;
    } else {
        ss << "  Message Type   : " <<
                         get_msg_type_name(msg_type) << std::endl;
        if (msg_type == mc_msg_type_t::ROUTE) {
            ss << "  Group Address  : " <<
                             nas_mc_ip_to_string(group_addr) << std::endl;
            if (xg_entry) {
                ss << "  Source Address : *" << std::endl;
            } else {
                ss << "  Source Address : " <<
                             nas_mc_ip_to_string(source_addr) << std::endl;
            }
        }
        if (have_ifindex) {
            ss << "  Ifindex        : " << ifindex << std::endl;
        } else {
            ss << "  Ifindex        : -" << std::endl;
        }
    }
    ss << std::endl;
    return ss.str();
}

class nas_mc_msg_queue
{
public:
    // Make class as singleton
    static nas_mc_msg_queue& get_instance()
    {
        static nas_mc_msg_queue inst;
        return inst;
    }
    nas_mc_msg_queue(const nas_mc_msg_queue&) = delete;
    nas_mc_msg_queue& operator=(const nas_mc_msg_queue&) = delete;
    nas_mc_msg_queue(nas_mc_msg_queue&&) = delete;
    nas_mc_msg_queue& operator=(nas_mc_msg_queue&&) = delete;

    void push(const mc_snooping_msg_t& msg, bool sync = false)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        _pending_msg.push({msg, sync});
        _req_cond.notify_one();
        if (sync) {
            // wait for processing finish
            _ack_cond.wait(lock);
        }
    }

    void wait_for_msg(void)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        if (_pending_msg.empty()) {
            // check if there is pending msg
            _req_cond.wait(lock, [this](){return !_pending_msg.empty();});
        }
    }

    bool pop(mc_snooping_msg_t& msg, bool& is_sync)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        if (_pending_msg.empty()) {
            return false;
        }
        auto& q_item = _pending_msg.front();
        msg = q_item.first;
        is_sync = q_item.second;
        _pending_msg.pop();
        return true;
    }

    void proc_finish()
    {
        _ack_cond.notify_one();
    }

private:
    nas_mc_msg_queue(){}
    ~nas_mc_msg_queue(){}

    // Queue to store messages pending for main thread to process
    std::queue<std::pair<mc_snooping_msg_t, bool>> _pending_msg;

    std::mutex _mutex;
    std::condition_variable _req_cond;
    std::condition_variable _ack_cond;
};

/**
  * Data struction used to cache multicast status, multicast router ports
  * and multicast route entry
  **/

struct mc_route_info_t
{
    // NDI multicast group ID
    ndi_obj_id_t ndi_group_id;
    // List of member port and NDI member ID for multicast host
    std::unordered_map<hal_ifindex_t, ndi_obj_id_t> router_member_list;
    // List of member port and NDI member ID for multicast router
    std::unordered_map<hal_ifindex_t, ndi_obj_id_t> host_member_list;
};

using mc_route_map_t =
        std::unordered_map<mc_entry_key_t, mc_route_info_t, _mc_entry_key_hash, _mc_entry_key_equal>;

struct mc_snooping_info_t
{
    // List of multicast router ports of ipv4 family
    std::set<hal_ifindex_t> ipv4_mrouter_list;
    // List of multicast router ports of ipv6 family
    std::set<hal_ifindex_t> ipv6_mrouter_list;
    // List of multicast route entry
    mc_route_map_t route_list;
};

// Cache of multicast snooping units indexed with NPU_ID and VLAN ID
using mc_snooping_npu_info_t = std::unordered_map<hal_vlan_id_t, mc_snooping_info_t>;

class nas_mc_snooping
{
public:
    // Make class as singleton
    static nas_mc_snooping& get_instance()
    {
        static nas_mc_snooping inst;
        return inst;
    }
    nas_mc_snooping(const nas_mc_snooping&) = delete;
    nas_mc_snooping& operator=(const nas_mc_snooping&) = delete;
    nas_mc_snooping(nas_mc_snooping&&) = delete;
    nas_mc_snooping& operator=(nas_mc_snooping&&) = delete;


    // Check if cache could/need to be updated by attributes in multicast snooping
    // message
    bool update_needed(const mc_snooping_msg_t& msg_info);
    // Update the cache based on multicast snooping message
    void update(const mc_snooping_msg_t& msg_info);
    // Get cached information for multicast router,
    // and store them in multicast message data
    void get_mrouter_ndi_info(mc_snooping_msg_t& msg_info);
    // Get cached NDI IDs for multicast entry, group and member,
    // and store them in multicast message data
    void get_route_ndi_info(mc_snooping_msg_t& msg_info);

    // Clear all multicast snooping entries of specified VLAN and IP family from cache
    void flush(hal_vlan_id_t vlan_id, mc_event_type_t ip_type);

    // Delete all multicast snooping entries of specified VLAN and IP family on NPU
    t_std_error delete_vlan_entries(hal_vlan_id_t vlan_id, mc_event_type_t ip_type);
    // Delete all multicast snooping entries of specified VLAN and interface on NPU
    t_std_error delete_intf_entries(npu_id_t npu_id, bool all_vlan, hal_vlan_id_t vlan_id,
                                    hal_ifindex_t ifindex);
    // Dump all vlan cache entries to log
    std::string dump_vlan_entries(npu_id_t npu_id, hal_vlan_id_t vlan_id);
private:
    nas_mc_snooping(){}
    ~nas_mc_snooping(){}

    // Check if multicast is enable for specific VLAN and IP type
    bool enabled(mc_event_type_t req_type, hal_vlan_id_t vlan_id);

    // Indicate if multicast snooping is enabled for each vlan
    std::unordered_map<hal_vlan_id_t, std::pair<bool, bool>> _vlan_enabled;
    // Snooping info for each NPU
    std::unordered_map<npu_id_t, mc_snooping_npu_info_t> _npu_info;
};

static const char *nas_mc_entry_tag(hal_ip_addr_t src_ip, hal_ip_addr_t dst_ip,
                                    bool is_xg)
{
    static char str_buf[TAG_PRINT_BUF_LEN + 1];
    size_t buf_size = TAG_PRINT_BUF_LEN;
    char *buf_p = str_buf;
    snprintf(buf_p, buf_size, "(%s, ", is_xg ? "*" : nas_mc_ip_to_string(src_ip));
    buf_p += strlen(buf_p);
    buf_size -= strlen(buf_p);
    if (buf_size == 0) {
        return str_buf;
    }
    snprintf(buf_p, buf_size, "%s)", nas_mc_ip_to_string(dst_ip));
    return str_buf;
}

static const char *nas_mc_entry_key_tag(const mc_entry_key_t& entry_key)
{
    return nas_mc_entry_tag(entry_key.src_ip, entry_key.dst_ip, entry_key.is_xg);
}

static inline nas_mc_msg_queue& pending_msg()
{
    return nas_mc_msg_queue::get_instance();
}
// API to enable/disable multicast snooping
void nas_mc_change_snooping_status(mc_event_type_t req_type, hal_vlan_id_t vlan_id, bool enable)
{
    pending_msg().push({req_type, vlan_id, mc_oper_type_t::STATUS, enable});
}

// API to add multicast router port
void nas_mc_add_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push({req_type, vlan_id, mc_oper_type_t::ADD, true, mc_msg_type_t::MROUTER,
                        true, ifindex});
}

// API to delete mrouter port
void nas_mc_del_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push({req_type, vlan_id, mc_oper_type_t::DELETE, true, mc_msg_type_t::MROUTER,
                        true, ifindex});
}

// API to add multicast route entry
void nas_mc_add_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex)
{
    if (have_ifindex) {
        pending_msg().push({req_type, vlan_id, mc_oper_type_t::ADD, true, mc_msg_type_t::ROUTE,
                           have_ifindex, ifindex, false, group_addr, is_xg, src_addr});
    } else {
        size_t max_npu = nas_switch_get_max_npus();
        for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
            pending_msg().push({req_type, vlan_id, mc_oper_type_t::ADD, true, mc_msg_type_t::ROUTE,
                               have_ifindex, static_cast<hal_ifindex_t>(npu_id), false,
                               group_addr, is_xg, src_addr});
        }
    }
}

// API to delete multicast route entry
void nas_mc_del_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex)
{
    if (have_ifindex) {
        pending_msg().push({req_type, vlan_id, mc_oper_type_t::DELETE, true, mc_msg_type_t::ROUTE,
                            have_ifindex, ifindex, false, group_addr, is_xg, src_addr});
    } else {
        size_t max_npu = nas_switch_get_max_npus();
        for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
            pending_msg().push({req_type, vlan_id, mc_oper_type_t::DELETE, true, mc_msg_type_t::ROUTE,
                               have_ifindex, static_cast<hal_ifindex_t>(npu_id), false,
                               group_addr, is_xg, src_addr});
        }
    }
}

// API to delete all route entries for VLAN member interface
void nas_mc_cleanup_vlan_member(hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push({mc_event_type_t::IGMP_MLD, vlan_id, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ifindex}, true);
}

// API to delete all route entries for interface
void nas_mc_cleanup_interface(hal_ifindex_t ifindex)
{
    pending_msg().push({mc_event_type_t::IGMP_MLD, 0, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ifindex, true}, true);
}

// API to delete all route entries for VLAN
void nas_mc_cleanup_vlan(hal_vlan_id_t vlan_id)
{
    pending_msg().push({mc_event_type_t::IGMP_MLD, vlan_id, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ALL_INTERFACES}, true);
}

struct mc_npu_port_t
{
    npu_id_t npu_id;
    nas_int_type_t port_type;
    union {
        npu_port_t port_id;
        hal_vlan_id_t vlan_id;
        lag_id_t lag_id;
    };
};

static t_std_error ifindex_to_npu_port(hal_ifindex_t ifindex, mc_npu_port_t& npu_port)
{
    interface_ctrl_t intf_ctrl;
    t_std_error rc = STD_ERR_OK;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = ifindex;

    if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return STD_ERR(MCAST,FAIL, rc);
    }

    npu_port.npu_id = intf_ctrl.npu_id;
    npu_port.port_type = intf_ctrl.int_type;
    if (intf_ctrl.int_type == nas_int_type_LAG) {
        npu_port.lag_id = intf_ctrl.lag_id;
    } else if (intf_ctrl.int_type == nas_int_type_VLAN) {
        npu_port.vlan_id = intf_ctrl.vlan_id;
    } else {
        npu_port.port_id = intf_ctrl.port_id;
    }

    return STD_ERR_OK;
}

const bool DEFAULT_MC_SNOOPING_ENABLED = true;

static std::unordered_map<npu_id_t, ndi_obj_id_t>& default_group_list =
        *new std::unordered_map<npu_id_t, ndi_obj_id_t>{};

static t_std_error get_default_group_id(npu_id_t npu_id, ndi_obj_id_t& group_id)
{
    if (default_group_list.find(npu_id) == default_group_list.end()) {
        return STD_ERR(MCAST, PARAM, 0);
    }
    group_id = default_group_list[npu_id];
    return STD_ERR_OK;
}

bool nas_mc_snooping::enabled(mc_event_type_t req_type, hal_vlan_id_t vlan_id)
{
    auto itor = _vlan_enabled.find(vlan_id);
    if (itor == _vlan_enabled.end()) {
        return DEFAULT_MC_SNOOPING_ENABLED;
    }

    switch(req_type) {
    case mc_event_type_t::IGMP:
        return itor->second.first;
    case mc_event_type_t::MLD:
        return itor->second.second;
    case mc_event_type_t::IGMP_MLD:
        return itor->second.first || itor->second.second;
    }

    return false;
}

t_std_error nas_mc_snooping::delete_vlan_entries(hal_vlan_id_t vlan_id, mc_event_type_t ip_type)
{
    t_std_error rc, ret_val = STD_ERR_OK;

    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete all %s entries of VLAN %d from NPU",
                     ip_type == mc_event_type_t::IGMP_MLD ? "IPv4 and IPv6" :
                                (ip_type == mc_event_type_t::IGMP ? "IPv4" : "IPv6"),
                     vlan_id);
    for (auto& npu_info: _npu_info) {
        auto npu_id = npu_info.first;
        auto vlan_it = npu_info.second.find(vlan_id);
        if (vlan_it == npu_info.second.end()) {
            continue;
        }
        auto& route_list = vlan_it->second.route_list;
        for (auto& route_info: route_list) {
            if (!_is_af_match_ip_type(route_info.first.dst_ip.af_index, ip_type)) {
                continue;
            }
            ndi_mcast_entry_t mc_entry{vlan_id,
                                       route_info.first.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                       route_info.first.dst_ip,
                                       route_info.first.src_ip};
            rc = ndi_mcast_entry_delete(npu_id, &mc_entry);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC",
                               "Failed to delete multicast entry of %s and VLAN %d",
                               nas_mc_entry_key_tag(route_info.first),
                               vlan_id);
                ret_val = rc;
            }
            for (auto& rt_mbr: route_info.second.router_member_list) {
                rc = ndi_l2mc_group_delete_member(npu_id, rt_mbr.second);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group mrouter member");
                    ret_val = rc;
                }
            }
            for (auto& hst_mbr: route_info.second.host_member_list) {
                if (route_info.second.router_member_list.find(hst_mbr.first) !=
                    route_info.second.router_member_list.end()) {
                    // Already deleted from router list
                    continue;
                }
                rc = ndi_l2mc_group_delete_member(npu_id, hst_mbr.second);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group host member");
                    ret_val = rc;
                }
            }
            ndi_obj_id_t def_grp_id;
            rc = get_default_group_id(npu_id, def_grp_id);
            if ((rc == STD_ERR_OK) && (def_grp_id == route_info.second.ndi_group_id)) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "skip default multicast group deletion");
                continue;
            }
            rc = ndi_l2mc_group_delete(npu_id, route_info.second.ndi_group_id);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete multicast group");
                ret_val = rc;
            }
        }
    }

    return ret_val;
}

t_std_error nas_mc_snooping::delete_intf_entries(npu_id_t npu_id, bool all_vlan, hal_vlan_id_t vlan_id,
                                                 hal_ifindex_t ifindex)
{
    t_std_error rc, ret_val = STD_ERR_OK;

    if (all_vlan) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete group members of ifindex %d for all VLANs from NPU",
                         ifindex);
    } else {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete group members of ifindex %d for VLAN %d from NPU",
                         ifindex, vlan_id);
    }
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache", npu_id);
        return STD_ERR(MCAST, PARAM, 0);
    }
    typename std::remove_reference<decltype(npu_it->second)>::type::iterator vlan_it;
    if (all_vlan) {
        vlan_it = npu_it->second.begin();
    } else {
        vlan_it = npu_it->second.find(vlan_id);
    }
    if (vlan_it == npu_it->second.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "VLAN not found in cache");
        return STD_ERR(MCAST, PARAM, 0);
    }

    while (vlan_it != npu_it->second.end()) {
        auto& route_list = vlan_it->second.route_list;
        vlan_id = vlan_it->first;
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Handling interface entry cleanup for VLAN %d", vlan_id);
        for (auto& route_info: route_list) {
            bool del_entry = false;
            auto mbr_it = route_info.second.host_member_list.find(ifindex);
            auto rtr_mbr_it = route_info.second.router_member_list.find(ifindex);
            if (mbr_it != route_info.second.host_member_list.end()) {
                rc = ndi_l2mc_group_delete_member(npu_id, mbr_it->second);
                if (rc == STD_ERR_OK) {
                    if (route_info.second.host_member_list.size() == 1) {
                        del_entry = true;
                    }
                } else {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group host member");
                    ret_val = rc;
                }
            } else if ((mbr_it == route_info.second.host_member_list.end()) &&
                       (rtr_mbr_it != route_info.second.router_member_list.end())) {
                /* if port is not found in membership list check if it is mrouter
                   port, if yes delete it */
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d is mrouter in %s , delete it:",
                                 ifindex, nas_mc_entry_key_tag(route_info.first));
                rc = ndi_l2mc_group_delete_member(npu_id, rtr_mbr_it->second);
                if (rc != STD_ERR_OK) {
                   NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group mrouter member");
                   ret_val = rc;
                }
            } else if (!all_vlan) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d not found in entry %s member list:",
                                 ifindex, nas_mc_entry_key_tag(route_info.first));
                for (auto& mbr_info: route_info.second.host_member_list) {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "  ifindex %d => member_id %lu",
                                     mbr_info.first, mbr_info.second);
                }
            }
            if (del_entry) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No host member in group, entry will be deleted");
                ndi_mcast_entry_t mc_entry{vlan_id,
                                           route_info.first.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                           route_info.first.dst_ip,
                                           route_info.first.src_ip};
                rc = ndi_mcast_entry_delete(npu_id, &mc_entry);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC",
                                   "Failed to delete multicast entry of group %s and VLAN %d",
                                   nas_mc_entry_key_tag(route_info.first),
                                   vlan_id);
                    ret_val = rc;
                }
                for (auto& rt_mbr: route_info.second.router_member_list) {
                    if (rt_mbr.first == ifindex) {
                        continue;
                    }
                    rc = ndi_l2mc_group_delete_member(npu_id, rt_mbr.second);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group mrouter member");
                        ret_val = rc;
                    }
                }
                rc = ndi_l2mc_group_delete(npu_id, route_info.second.ndi_group_id);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete multicast group");
                    ret_val = rc;
                }
            }
        }
        if (all_vlan) {
            ++ vlan_it;
        } else {
            break;
        }
    }

    return ret_val;
}

void nas_mc_snooping::flush(hal_vlan_id_t vlan_id, mc_event_type_t ip_type)
{
    for (auto& npu_info: _npu_info) {
        auto vlan_it = npu_info.second.find(vlan_id);
        if (vlan_it == npu_info.second.end()) {
            continue;
        }
        auto& route_list = vlan_it->second.route_list;
        for (auto ent_it = route_list.begin(); ent_it != route_list.end();) {
            if (_is_af_match_ip_type(ent_it->first.dst_ip.af_index, ip_type)) {
                ent_it = route_list.erase(ent_it);
            } else {
                ent_it ++;
            }
        }
        if (route_list.empty()) {
            npu_info.second.erase(vlan_it);
        }
    }
}

bool nas_mc_snooping::update_needed(const mc_snooping_msg_t& msg_info)
{
    if (msg_info.oper_type == mc_oper_type_t::STATUS) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "ALL-VLANs mode is not supported for status update");
            return false;
        }
        auto itor = _vlan_enabled.find(msg_info.vlan_id);
        if (itor == _vlan_enabled.end()) {
            return true;
        }
        if (msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            if (msg_info.enable != itor->second.first || msg_info.enable != itor->second.second) {
                return true;
            }
        } else {
            bool enabled =
                (msg_info.req_type == mc_event_type_t::IGMP ? itor->second.first : itor->second.second);
            if (enabled != msg_info.enable) {
                return true;
            } else {
                // Use duplicate enable/disable as trigger point to dump cache
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "\n%s\n",
                                 dump_vlan_entries(0, msg_info.vlan_id).c_str());
            }
        }
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need to update status in cache , current setting of VLAN %d: IGMP %s MLD %s",
                         itor->first, itor->second.first ? "Enabled" : "Disabled",
                         itor->second.second ? "Enabled" : "Disabled");
        // Default snoop status is enabled in BASE, so first time when snooping gets enabled.
        // status will be same and no trigger to update HW. So true is returned to trigger
        // update NPU with lookup key.
        return true;
    }

    if (!msg_info.all_vlan && !enabled(msg_info.req_type, msg_info.vlan_id)) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Mulitcast snooping for VLAN %d was not enabled",
                       msg_info.vlan_id);
        return false;
    }

    if (!msg_info.have_ifindex && msg_info.msg_type != mc_msg_type_t::ROUTE) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NULL port is only supported by route config");
        return false;
    }

    if (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES) {
        if (msg_info.oper_type != mc_oper_type_t::DELETE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Only delete is supported for VLAN update handling");
            return false;
        }
        return true;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NPU port from ifindex %d",
                           msg_info.ifindex);
            return false;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }
    if (_npu_info.find(npu_port.npu_id) == _npu_info.end() &&
        msg_info.oper_type == mc_oper_type_t::ADD) {
        return true;
    }

    typename std::remove_reference<decltype(_npu_info[npu_port.npu_id])>::type::iterator itor;
    if (msg_info.all_vlan) {
        itor = _npu_info[npu_port.npu_id].begin();
    } else {
        itor = _npu_info[npu_port.npu_id].find(msg_info.vlan_id);
    }
    if (itor == _npu_info[npu_port.npu_id].end()) {
        if (msg_info.oper_type == mc_oper_type_t::DELETE) {
            if (msg_info.all_vlan) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "NPU %d has no VLAN entry for delete",
                                 npu_port.npu_id);
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Entry for VLAN %d not exist for delete",
                                 msg_info.vlan_id);
            }
            return false;
        } else {
            return true;
        }
    }

    auto& snp_info = itor->second;
    if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
        auto ipv4_mr_itor = snp_info.ipv4_mrouter_list.find(msg_info.ifindex);
        auto ipv6_mr_itor = snp_info.ipv6_mrouter_list.find(msg_info.ifindex);
        if (msg_info.req_type == mc_event_type_t::IGMP) {
            if ((ipv4_mr_itor == snp_info.ipv4_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv4_mr_itor != snp_info.ipv4_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        } else if (msg_info.req_type == mc_event_type_t::MLD) {
            if ((ipv6_mr_itor == snp_info.ipv6_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv6_mr_itor != snp_info.ipv6_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        } else if (msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            if ((ipv4_mr_itor == snp_info.ipv4_mrouter_list.end() && ipv6_mr_itor == snp_info.ipv6_mrouter_list.end() &&
                 msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv4_mr_itor != snp_info.ipv4_mrouter_list.end() && ipv6_mr_itor != snp_info.ipv6_mrouter_list.end() &&
                 msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        }

        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d %s in mrouter list of VLAN %d", msg_info.ifindex,
                         msg_info.oper_type == mc_oper_type_t::ADD ? "already exists" : "not found",
                         itor->first);
    } else if (msg_info.msg_type == mc_msg_type_t::ROUTE){
        if (!_is_af_match_ip_type(msg_info.group_addr.af_index, msg_info.req_type)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Input group address  family %d is not matched with event type %d",
                           msg_info.group_addr.af_index, msg_info.req_type);
            return false;
        }
        if (!msg_info.xg_entry && !_is_af_match_ip_type(msg_info.source_addr.af_index, msg_info.req_type)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Input source address  family %d is not matched with event type %d",
                           msg_info.source_addr.af_index, msg_info.req_type);
            return false;
        }
        auto rt_itor = snp_info.route_list.find({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr});
        if (rt_itor == snp_info.route_list.end()) {
            if (msg_info.oper_type == mc_oper_type_t::DELETE) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Multicast group %s not found for delete",
                                 nas_mc_entry_tag(msg_info.source_addr, msg_info.group_addr, msg_info.xg_entry));
                return false;
            } else {
                return true;
            }
        }
        if (msg_info.have_ifindex) {
            auto& mbr_list = rt_itor->second.host_member_list;
            auto mbr_itor = mbr_list.find(msg_info.ifindex);
            if ((mbr_itor == mbr_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (mbr_itor != mbr_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d %s in host member list of VLAN %d group %s",
                                 msg_info.ifindex,
                                 msg_info.oper_type == mc_oper_type_t::ADD ? "already exists" : "not found",
                                 itor->first, nas_mc_ip_to_string(msg_info.group_addr));
            }
        } else {
            if (rt_itor->second.host_member_list.size() > 0) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "NULL group entry should not contain any host memeber");
                return false;
            }
            if (msg_info.oper_type == mc_oper_type_t::ADD) {
                return false;
            } else {
                return true;
            }
        }
    } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE){
        if (msg_info.oper_type != mc_oper_type_t::DELETE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Only delete is supported for interface update handling");
            return false;
        }
        return true;
    } else {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Unknown message type %d", msg_info.msg_type);
        return false;
    }

    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need to update mrouter or entry of VLAN %d", itor->first);
    return false;
}

void nas_mc_snooping::update(const mc_snooping_msg_t& msg_info)
{
    if (msg_info.oper_type == mc_oper_type_t::STATUS) {
        auto it = _vlan_enabled.find(msg_info.vlan_id);
        if (msg_info.req_type == mc_event_type_t::IGMP) {
            _vlan_enabled[msg_info.vlan_id] = std::make_pair(
                    msg_info.enable,
                    it == _vlan_enabled.end() ? DEFAULT_MC_SNOOPING_ENABLED : it->second.second);
        } else if (msg_info.req_type == mc_event_type_t::MLD){
            _vlan_enabled[msg_info.vlan_id] = std::make_pair(
                    it == _vlan_enabled.end() ? DEFAULT_MC_SNOOPING_ENABLED : it->second.first,
                    msg_info.enable);
        } else {
            _vlan_enabled[msg_info.vlan_id] = std::make_pair(msg_info.enable, msg_info.enable);
        }

        if (msg_info.enable) {
            return;
        }
    }

    if ((msg_info.oper_type == mc_oper_type_t::STATUS && !msg_info.enable) ||
        (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES)) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Flush cached %s snooping entries for VLAN %d",
                         msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                         (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                         msg_info.vlan_id);
        flush(msg_info.vlan_id, msg_info.req_type);
        return;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to get NPU port for ifindex %d",
                           msg_info.ifindex);
            return;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }

    if (_npu_info.find(npu_port.npu_id) == _npu_info.end()) {
        // Added slot for new NPU ID
        _npu_info.insert({npu_port.npu_id, mc_snooping_npu_info_t{}});
    }

    typename std::remove_reference<decltype(_npu_info[npu_port.npu_id])>::type::iterator itor;
    if (msg_info.all_vlan) {
        itor = _npu_info[npu_port.npu_id].begin();
    } else {
        itor = _npu_info[npu_port.npu_id].find(msg_info.vlan_id);
    }

    if (msg_info.oper_type == mc_oper_type_t::DELETE &&
        itor == _npu_info[npu_port.npu_id].end()) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "No VLAN found to be deleted");
        } else {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Entry for VLAN %d not exist for delete",
                           msg_info.vlan_id);
        }
        return;
    }

    if (msg_info.oper_type == mc_oper_type_t::ADD) {
        if (itor == _npu_info[npu_port.npu_id].end()) {
            _npu_info[npu_port.npu_id][msg_info.vlan_id] = mc_snooping_info_t{};
        }
        auto& snp_info = _npu_info[npu_port.npu_id].at(msg_info.vlan_id);
        if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
            NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Add mrouter ifindex %d to VLAN %d mrouter list",
                            msg_info.ifindex, msg_info.vlan_id);
            if (msg_info.req_type == mc_event_type_t::IGMP || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                snp_info.ipv4_mrouter_list.insert(msg_info.ifindex);
            }
            if (msg_info.req_type == mc_event_type_t::MLD || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                snp_info.ipv6_mrouter_list.insert(msg_info.ifindex);
            }

            // Add to mrouter interface to multicast entries
            for (auto& rt_info: snp_info.route_list) {
                auto mrt_itor = msg_info.mrouter_member_list.find(rt_info.first);
                if (mrt_itor != msg_info.mrouter_member_list.end() && std::get<1>(mrt_itor->second)) {
                    NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Add mrouter interface to multicast entry %s",
                                    nas_mc_entry_key_tag(rt_info.first));
                    if (std::get<2>(mrt_itor->second)) {
                        rt_info.second.ndi_group_id = std::get<3>(mrt_itor->second);
                    }
                    rt_info.second.router_member_list.insert({msg_info.ifindex, std::get<0>(mrt_itor->second)});
                }
            }
        } else if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
            auto it1 = snp_info.route_list.find({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr});
            if ((it1 == snp_info.route_list.end()) || (!msg_info.entry_exist)) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Add route entry: VLAN %d %s Group ID 0x%" PRIx64,
                                msg_info.vlan_id,
                                nas_mc_entry_tag(msg_info.source_addr, msg_info.group_addr, msg_info.xg_entry),
                                msg_info.group_id);

                snp_info.route_list[{msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr}] =
                        mc_route_info_t{msg_info.group_id};
                // Add all members for mrouter interface to new multicast entry
                decltype(snp_info.ipv4_mrouter_list)* mrouter_list_p = nullptr;
                if (msg_info.req_type == mc_event_type_t::IGMP) {
                    mrouter_list_p = &snp_info.ipv4_mrouter_list;
                } else {
                    mrouter_list_p = &snp_info.ipv6_mrouter_list;
                }
                for (auto mrt_ifindex: *mrouter_list_p) {
                    if (msg_info.router_member_list.find(mrt_ifindex) != msg_info.router_member_list.end()) {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Add mrouter ifindex %d to route member list",
                                        mrt_ifindex);
                        snp_info.route_list.at({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr}).
                            router_member_list.insert({mrt_ifindex, msg_info.router_member_list.at(mrt_ifindex)});
                    }
                }
            }
            if (msg_info.have_ifindex) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Add route member: VLAN %d group %s port %d member NDI_ID 0x%" PRIx64 " NDI grp id 0x%" PRIx64,
                                msg_info.vlan_id,nas_mc_entry_tag(msg_info.source_addr,
                                msg_info.group_addr,msg_info.xg_entry),
                                msg_info.ifindex, msg_info.member_id, msg_info.group_id);
                snp_info.route_list.at({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr}).host_member_list.
                            insert({msg_info.ifindex, msg_info.member_id});
            }
        }
    } else if (msg_info.oper_type == mc_oper_type_t::DELETE) {
        if (msg_info.all_vlan && msg_info.msg_type != mc_msg_type_t::INTERFACE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "ALL-VLANs mode is only supported for interface delete");
            return;
        }
        while(itor != _npu_info[npu_port.npu_id].end()) {
            auto& snp_info = itor->second;
            if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete mrouter ifindex %d from VLAN %d mrouter list",
                                msg_info.ifindex, itor->first);

                if (msg_info.req_type == mc_event_type_t::IGMP || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                    snp_info.ipv4_mrouter_list.erase(msg_info.ifindex);
                }
                if (msg_info.req_type == mc_event_type_t::MLD || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                    snp_info.ipv6_mrouter_list.erase(msg_info.ifindex);
                }

                // Delete from router member list
                for (auto& rt_info: snp_info.route_list) {
                    auto mrt_itor = msg_info.mrouter_member_list.find(rt_info.first);
                    if (mrt_itor != msg_info.mrouter_member_list.end() && !std::get<1>(mrt_itor->second)) {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete mrouter interface from multicast entry %s",
                                        nas_mc_entry_key_tag(rt_info.first));
                        rt_info.second.router_member_list.erase(msg_info.ifindex);
                        if (std::get<2>(mrt_itor->second)) {
                            rt_info.second.ndi_group_id = std::get<3>(mrt_itor->second);
                        }
                    }
                }
            } else if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
                auto it1 = snp_info.route_list.find({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr});
                if (it1 != snp_info.route_list.end()) {
                    if (msg_info.have_ifindex) {
                        auto& mbr_list = it1->second.host_member_list;
                        NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete route member: VLAN %d group %s port %d",
                                        itor->first, nas_mc_ip_to_string(msg_info.group_addr),
                                        msg_info.ifindex);
                        mbr_list.erase(msg_info.ifindex);
                        if (mbr_list.empty()) {
                            // If all members deleted, route entry will also be deleted
                            NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete empty route entry: VLAN %d group %s",
                                            itor->first, nas_mc_ip_to_string(msg_info.group_addr));
                            snp_info.route_list.erase(it1);
                        }
                    } else {
                        snp_info.route_list.erase(it1);
                    }
                }
            } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete ifindex %d from VLAN %d mrouter and route list",
                                msg_info.ifindex, itor->first);
                if (snp_info.ipv4_mrouter_list.find(msg_info.ifindex) != snp_info.ipv4_mrouter_list.end()) {
                    snp_info.ipv4_mrouter_list.erase(msg_info.ifindex);
                }
                if (snp_info.ipv6_mrouter_list.find(msg_info.ifindex) != snp_info.ipv6_mrouter_list.end()) {
                    snp_info.ipv6_mrouter_list.erase(msg_info.ifindex);
                }
                // Delete from router member list
                for (auto it = snp_info.route_list.begin(); it != snp_info.route_list.end();) {
                    auto mr_it = it->second.router_member_list.find(msg_info.ifindex);
                    if (mr_it != it->second.router_member_list.end()) {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Remove mrouter interface from multicast entry %s",
                                        nas_mc_entry_key_tag(it->first));
                        it->second.router_member_list.erase(mr_it);
                    }
                    auto hst_it = it->second.host_member_list.find(msg_info.ifindex);
                    if (hst_it != it->second.host_member_list.end()) {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Remove host interface from multicast entry %s",
                                        nas_mc_entry_key_tag(it->first));
                        it->second.host_member_list.erase(hst_it);
                    }
                    if (it->second.host_member_list.empty()) {
                        it = snp_info.route_list.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            if (snp_info.ipv4_mrouter_list.empty() && snp_info.ipv6_mrouter_list.empty() && snp_info.route_list.empty()) {
                // If there is no mrouter and route entry left for VLAN, VLAN unit
                // will be deleted
                NAS_MC_LOG_INFO("NAS-MC-PROC-CACHE", "Delete empty multicast unit for VLAN %d",
                                itor->first);
                itor = _npu_info[npu_port.npu_id].erase(itor);
            } else {
                ++ itor;
            }
            if (!msg_info.all_vlan) {
                break;
            }
        }
    }
}

void nas_mc_snooping::get_mrouter_ndi_info(mc_snooping_msg_t& msg_info)
{
    if (msg_info.msg_type != mc_msg_type_t::MROUTER) {
        return;
    }
    mc_npu_port_t npu_port;
    t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
    if (rc != STD_ERR_OK ||
        _npu_info.find(npu_port.npu_id) == _npu_info.end()) {
        return;
    }
    auto itor = _npu_info[npu_port.npu_id].find(msg_info.vlan_id);
    if (itor == _npu_info[npu_port.npu_id].end()) {
        return;
    }
    for (auto& route_info: _npu_info[npu_port.npu_id][msg_info.vlan_id].route_list) {
        if (!_is_af_match_ip_type(route_info.first.dst_ip.af_index, msg_info.req_type)) {
            continue;
        }
        auto rt_itor = route_info.second.router_member_list.find(msg_info.ifindex);
        auto hst_itor = route_info.second.host_member_list.find(msg_info.ifindex);
        if (msg_info.oper_type == mc_oper_type_t::ADD) {
            if (rt_itor == route_info.second.router_member_list.end()) {
                if (hst_itor == route_info.second.host_member_list.end()) {
                    bool upd_dft_group = (route_info.second.router_member_list.empty() &&
                                          route_info.second.host_member_list.empty());
                    // mrouter interface is not set host member, give the NDI group ID and mark
                    // member as non-existent (need to be added)
                    msg_info.mrouter_member_list.insert({route_info.first,
                                                         std::make_tuple(route_info.second.ndi_group_id, false,
                                                                         upd_dft_group, 0)});
                } else {
                    // mrouter interface is also set as host member, give NDI member ID and mark it
                    // as existent
                    msg_info.mrouter_member_list.insert({route_info.first,
                                                         std::make_tuple(hst_itor->second, true, false, 0)});
                }
            }
        } else if (msg_info.oper_type == mc_oper_type_t::DELETE) {
            if (rt_itor != route_info.second.router_member_list.end()) {
                if (hst_itor != route_info.second.host_member_list.end()) {
                    // mrouter interface is also set as host member, mark it as not to be deleted
                    msg_info.mrouter_member_list.insert({route_info.first,
                                std::make_tuple(hst_itor->second, false, false, 0)});
                } else {
                    // mrouter interface is only in router member list, give the NDI member ID that
                    // will be deleted
                    bool upd_dft_group = (route_info.second.router_member_list.size() == 1 &&
                                          route_info.second.host_member_list.empty());
                    msg_info.mrouter_member_list.insert({route_info.first,
                                std::make_tuple(rt_itor->second, true, upd_dft_group, route_info.second.ndi_group_id)});
                }
            }
        }
    }
}

void nas_mc_snooping::get_route_ndi_info(mc_snooping_msg_t& msg_info)
{
    if (msg_info.msg_type != mc_msg_type_t::ROUTE) {
        return;
    }
    msg_info.entry_exist = false;
    msg_info.member_is_mrouter = false;
    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            return;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }
    if (_npu_info.find(npu_port.npu_id) == _npu_info.end()) {
        return;
    }
    auto itor = _npu_info[npu_port.npu_id].find(msg_info.vlan_id);
    if (itor == _npu_info[npu_port.npu_id].end()) {
        return;
    }
    auto grp_itor = itor->second.route_list.find({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr});
    if (grp_itor == itor->second.route_list.end()) {
        if (msg_info.oper_type == mc_oper_type_t::ADD) {
            // Add all mrouter interfaces to list for new multicast entry
            decltype(itor->second.ipv4_mrouter_list)* mrouter_list_p = nullptr;
            if (msg_info.req_type == mc_event_type_t::IGMP) {
                mrouter_list_p = &itor->second.ipv4_mrouter_list;
            } else {
                mrouter_list_p = &itor->second.ipv6_mrouter_list;
            }
            for (auto rt_ifindex: *mrouter_list_p) {
                msg_info.router_member_list.insert({rt_ifindex, 0});
            }
        }
        return;
    }
    msg_info.entry_exist = true;
    msg_info.group_id = grp_itor->second.ndi_group_id;
    if (msg_info.have_ifindex) {
        auto mrt_itor = grp_itor->second.router_member_list.find(msg_info.ifindex);
        if (mrt_itor != grp_itor->second.router_member_list.end()) {
            msg_info.member_is_mrouter = true;
            msg_info.member_id = mrt_itor->second;
        } else {
            auto host_itor = grp_itor->second.host_member_list.find(msg_info.ifindex);
            if (host_itor != grp_itor->second.host_member_list.end()) {
                msg_info.member_id = host_itor->second;
            }
        }
        if (grp_itor->second.host_member_list.size() > 1) {
            msg_info.last_host_member = false;
        } else {
            msg_info.last_host_member = true;
            if (msg_info.oper_type == mc_oper_type_t::DELETE) {
                // When last host member to be deleted, the corresponding mc entry will
                // also be deleted. The router member list is picked up for next step of
                // deleting them from NPU
                msg_info.router_member_list = grp_itor->second.router_member_list;
            }
        }
    } else {
        msg_info.last_host_member = true;
        if (msg_info.oper_type == mc_oper_type_t::DELETE) {
            msg_info.router_member_list = grp_itor->second.router_member_list;
        }
    }
}

std::string nas_mc_snooping::dump_vlan_entries(npu_id_t npu_id, hal_vlan_id_t vlan_id)
{
    auto itor = _npu_info.find(npu_id);
    if (itor == _npu_info.end()) {
        itor = _npu_info.begin();
        if (itor == _npu_info.end()) {
            return "";
        } else {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Use NPU %d instead of default NPU", itor->first);
        }
    }
    auto vlan_itor = itor->second.find(vlan_id);
    if (vlan_itor == itor->second.end()) {
        return "";
    }
    auto& snp_info = vlan_itor->second;
    std::ostringstream ss;
    ss << "---------------------------------------" << std::endl;
    ss << "     Cache of VLAN " << vlan_itor->first << std::endl;
    ss << "---------------------------------------" << std::endl;
    ss << " ipv4 mrouters: ";
    for (auto ifindex: snp_info.ipv4_mrouter_list) {
        ss << ifindex << " ";
    }
    ss << std::endl;
    ss << " ipv6 mrouters: ";
    for (auto ifindex: snp_info.ipv6_mrouter_list) {
        ss << ifindex << " ";
    }
    ss << std::endl;
    ss << " entries:" << std::endl;
    for (auto& route_info: snp_info.route_list) {
        ss << "  " << nas_mc_entry_key_tag(route_info.first) << " ==> R:{";
        for (auto& mbr_info: route_info.second.router_member_list) {
            ss << mbr_info.first << " ";
        }
        ss << "} H:{";
        for (auto& mbr_info: route_info.second.host_member_list) {
            ss << mbr_info.first << " ";
        }
        ss << "}";
        ss << std::endl;
    }
    return ss.str();
}

static t_std_error nas_mc_npu_add_group_member(ndi_obj_id_t group_id, const mc_npu_port_t& npu_port,
                                               ndi_obj_id_t& member_id)
{
    if (npu_port.port_type == nas_int_type_LAG) {
        return ndi_l2mc_group_add_lag_member(npu_port.npu_id, group_id, npu_port.lag_id,
                                             &member_id);
    } else if (npu_port.port_type == nas_int_type_VLAN) {
        // TODO: currently not supported
        return STD_ERR_OK;
    } else {
        return ndi_l2mc_group_add_port_member(npu_port.npu_id, group_id, npu_port.port_id,
                                              &member_id);
    }
}

static inline nas_mc_snooping& cache()
{
    return nas_mc_snooping::get_instance();
}

static t_std_error nas_mc_config_hw(mc_snooping_msg_t& msg_info)
{

    if (msg_info.oper_type == mc_oper_type_t::STATUS) {

        ndi_vlan_mcast_lookup_key_type_t key = NAS_NDI_VLAN_MCAST_LOOKUP_KEY_MACDA;

        if(msg_info.enable) {
           key = NAS_NDI_VLAN_MCAST_LOOKUP_KEY_XG_AND_SG;
        }
        if ((msg_info.req_type == mc_event_type_t::IGMP) || (msg_info.req_type == mc_event_type_t::MLD)) {
            uint32_t af = msg_info.req_type == mc_event_type_t::IGMP?NDI_IPV4_VERSION:NDI_IPV6_VERSION;
            if (STD_ERR_OK != (ndi_vlan_set_mcast_lookup_key(0,msg_info.vlan_id,af,key))) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW",
                                "Failed to set %s VLAN MCAST lookup key to %d on VLAN %d",
                                msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD",
                                key, msg_info.vlan_id);
            }else
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW",
                                "Set %s VLAN MCAST lookup key to %d on VLAN %d success",
                                msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD",
                                key, msg_info.vlan_id);
        }
    }

    if (msg_info.oper_type == mc_oper_type_t::STATUS ||
        (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES)) {
        if (msg_info.oper_type == mc_oper_type_t::STATUS && msg_info.enable) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW",
                             "Nothing to be done by NPU to enable multicast snooping");
        } else {
            if (msg_info.oper_type == mc_oper_type_t::STATUS) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW",
                                 "%s snooping for VLAN %d is disabled, all related multicast entries will be deleted from NPU",
                                  msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                                  (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                                  msg_info.vlan_id);
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Delete all %s snooping entries from NPU for VLAN %d",
                                  msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                                  (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                                  msg_info.vlan_id);
            }
            t_std_error rc = cache().delete_vlan_entries(msg_info.vlan_id, msg_info.req_type);
            if (rc != STD_ERR_OK) {
                // Log the error info and return success to continue to cache flushing
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete all entries for VLAN %d: rc=%d", msg_info.vlan_id, rc);
            }
        }
        return STD_ERR_OK;
    }

    mc_npu_port_t npu_port;
    t_std_error rc;
    if (msg_info.have_ifindex) {
        rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to get NPU port for ifindex %d", msg_info.ifindex);
            return rc;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }
    if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
        if (msg_info.oper_type == mc_oper_type_t::ADD) {
            // Add mrouter interface to all multicast entries under same VLAN
            for (auto& mrt_member: msg_info.mrouter_member_list) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Add mrouter interface %d to mc route entry %s",
                                msg_info.ifindex, nas_mc_ip_to_string(mrt_member.first.dst_ip));
                ndi_obj_id_t mbr_id;
                if (!std::get<1>(mrt_member.second)) {
                    ndi_obj_id_t group_id = std::get<0>(mrt_member.second);
                    if (std::get<2>(mrt_member.second)) {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Entry linked default group, need to to create new group");
                        rc = ndi_l2mc_group_create(npu_port.npu_id, &group_id);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create new group");
                            continue;
                        }
                        NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Re-create multicast entry to link new group");
                        ndi_mcast_entry_t mc_entry{msg_info.vlan_id,
                                                   mrt_member.first.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                                   mrt_member.first.dst_ip,
                                                   mrt_member.first.src_ip};
                        rc = ndi_mcast_entry_delete(npu_port.npu_id, &mc_entry);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete old multicast entry");
                            continue;
                        }
                        mc_entry.group_id = group_id;
                        rc = ndi_mcast_entry_create(npu_port.npu_id, &mc_entry);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create new multicast entry");
                            continue;
                        }
                        std::get<3>(mrt_member.second) = group_id;
                    }
                    rc = nas_mc_npu_add_group_member(group_id, npu_port, mbr_id);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to add multicast group member");
                        continue;
                    }
                    std::get<0>(mrt_member.second) = mbr_id;
                    std::get<1>(mrt_member.second) = true;
                }
            }
        } else if (msg_info.oper_type == mc_oper_type_t::DELETE) {
            for (auto& mrt_member: msg_info.mrouter_member_list) {
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Delete mrouter interface %d from mc route entry %s",
                                msg_info.ifindex, nas_mc_ip_to_string(mrt_member.first.dst_ip));
                if (std::get<1>(mrt_member.second)) {
                    rc = ndi_l2mc_group_delete_member(npu_port.npu_id, std::get<0>(mrt_member.second));
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("nas-mc-proc-hw", "failed to delete multicast group member, npu %d port %d",
                                       npu_port.npu_id, npu_port.port_id);
                        continue;
                    }
                    if (std::get<2>(mrt_member.second)) {
                        ndi_obj_id_t dft_group_id;
                        rc = get_default_group_id(npu_port.npu_id, dft_group_id);
                        if (rc != STD_ERR_OK) {
                            continue;
                        }
                        NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Re-create multicast entry to link default group");
                        ndi_mcast_entry_t mc_entry{msg_info.vlan_id,
                                                   mrt_member.first.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                                   mrt_member.first.dst_ip,
                                                   mrt_member.first.src_ip};
                        rc = ndi_mcast_entry_delete(npu_port.npu_id, &mc_entry);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete old multicast entry");
                            continue;
                        }
                        rc = ndi_l2mc_group_delete(npu_port.npu_id, std::get<3>(mrt_member.second));
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete old multicast group");
                            continue;
                        }
                        mc_entry.group_id = dft_group_id;
                        rc = ndi_mcast_entry_create(npu_port.npu_id, &mc_entry);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create new multicast entry");
                            continue;
                        }
                        std::get<3>(mrt_member.second) = dft_group_id;
                    }
                    std::get<0>(mrt_member.second) = 0;
                    std::get<1>(mrt_member.second) = false;
                }
            }
        } else {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Unsupported operation type %d for mrouter",
                           msg_info.oper_type);
            return STD_ERR(MCAST, PARAM, 0);
        }
    } else if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
        if (msg_info.oper_type == mc_oper_type_t::ADD) {
            ndi_obj_id_t group_id, default_grp_id;
            rc = get_default_group_id(npu_port.npu_id, default_grp_id);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to get default multicast group for NPU %d",
                               npu_port.npu_id);
                return rc;
            }
            if (msg_info.entry_exist && (msg_info.group_id == default_grp_id)) {
                /* This case is SG entry exists with no ports and a port gets added.
                   Delete this route entry, mark entry exist false the follow
                   through code will allocate new Grp ID and route will be
                   associate with it */
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Delete route entry linked with default group");
                ndi_mcast_entry_t mc_entry{msg_info.vlan_id,
                                           msg_info.xg_entry ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                           msg_info.group_addr,
                                           msg_info.source_addr};
                rc = ndi_mcast_entry_delete(npu_port.npu_id, &mc_entry);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete old multicast entry with default group ID");
                    return rc;
                }
                msg_info.entry_exist = false;
                msg_info.group_id = 0;
            }
            if (!msg_info.entry_exist) {
                if (!msg_info.have_ifindex && msg_info.router_member_list.empty()) {
                    group_id = default_grp_id;
                    NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Use global default group with ID 0x%" PRIx64, group_id);
                } else {
                    rc = ndi_l2mc_group_create(npu_port.npu_id, &group_id);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create multicast group");
                        return rc;
                    }
                    NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "New multicast group created, group_id = 0x%" PRIx64,
                                    group_id);
                }
                msg_info.group_id = group_id;

                // Add all members for mrouter interface
                for (auto& rt_mbr: msg_info.router_member_list) {
                    mc_npu_port_t np;
                    rc = ifindex_to_npu_port(rt_mbr.first, np);
                    if (rc != STD_ERR_OK || np.npu_id != npu_port.npu_id) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "NPU port for ifindex %d not found or matched",
                                       rt_mbr.first);
                        continue;
                    }
                    ndi_obj_id_t mbr_id;
                    rc = nas_mc_npu_add_group_member(group_id, np, mbr_id);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to add member for ifindex %d", rt_mbr.first);
                        continue;
                    }
                    rt_mbr.second = mbr_id;
                    NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Router member of ifindex %d added to group, member_id = 0x%"
                                    PRIx64, rt_mbr.first, mbr_id);
                    if (rt_mbr.first == msg_info.ifindex) {
                        msg_info.member_is_mrouter = true;
                        msg_info.member_id = mbr_id;
                    }
                }
            }
            if (!msg_info.member_is_mrouter && msg_info.have_ifindex) {
                ndi_obj_id_t mbr_id;
                rc = nas_mc_npu_add_group_member(msg_info.group_id, npu_port, mbr_id);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to add multicast group member");
                    if (!msg_info.entry_exist) {
                        //rollback group create
                        for (auto& rt_mbr: msg_info.router_member_list) {
                            ndi_l2mc_group_delete_member(npu_port.npu_id, rt_mbr.second);
                        }
                        ndi_l2mc_group_delete(npu_port.npu_id, msg_info.group_id);
                    }
                    return rc;
                }
                msg_info.member_id = mbr_id;
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Host member of ifindex %d added to group, member_id = 0x%"
                                PRIx64, msg_info.ifindex, mbr_id);
            }
            if (!msg_info.entry_exist) {
                ndi_mcast_entry_t mc_entry{msg_info.vlan_id,
                                           msg_info.xg_entry ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                           msg_info.group_addr,
                                           msg_info.source_addr};
                mc_entry.group_id = msg_info.group_id;
                rc = ndi_mcast_entry_create(npu_port.npu_id, &mc_entry);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create multicast entry");
                    // rollback group create
                    if (!msg_info.member_is_mrouter && msg_info.have_ifindex) {
                        ndi_l2mc_group_delete_member(npu_port.npu_id, msg_info.member_id);
                    }
                    for (auto& rt_mbr: msg_info.router_member_list) {
                        ndi_l2mc_group_delete_member(npu_port.npu_id, rt_mbr.second);
                    }
                    if (msg_info.have_ifindex || !msg_info.router_member_list.empty()) {
                        ndi_l2mc_group_delete(npu_port.npu_id, msg_info.group_id);
                    }
                    return rc;
                }
                NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "New multicast entry for group %s created",
                                nas_mc_ip_to_string(msg_info.group_addr));
            }
        } else if (msg_info.oper_type == mc_oper_type_t::DELETE) {
            if (!msg_info.member_is_mrouter || msg_info.last_host_member) {
                if (msg_info.have_ifindex) {
                    rc = ndi_l2mc_group_delete_member(npu_port.npu_id, msg_info.member_id);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete mc group member");
                        return rc;
                    }
                }
                if (msg_info.last_host_member) {
                    NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Delete entry for %s of vlan %d that point to empty group",
                                    nas_mc_ip_to_string(msg_info.group_addr), msg_info.vlan_id);
                    ndi_mcast_entry_t mc_entry{msg_info.vlan_id,
                                               msg_info.xg_entry ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                               msg_info.group_addr,
                                               msg_info.source_addr};
                    rc = ndi_mcast_entry_delete(npu_port.npu_id, &mc_entry);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete multicast entry");
                        return rc;
                    }
                    // Delete all members of mrouter interface from mc group
                    for (auto& rt_mbr: msg_info.router_member_list) {
                        if (rt_mbr.first == msg_info.ifindex) {
                            continue;
                        }
                        rc = ndi_l2mc_group_delete_member(npu_port.npu_id, rt_mbr.second);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete mc group member of ifindex %d",
                                           rt_mbr.first);
                            return rc;
                        }
                    }
                    if (msg_info.have_ifindex || !msg_info.router_member_list.empty()) {
                        rc = ndi_l2mc_group_delete(npu_port.npu_id, msg_info.group_id);
                        if (rc != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete multicast group");
                            return rc;
                        }
                    } else {
                        NAS_MC_LOG_INFO("NAS-MC-PROC-HW", "Global default group is used, do not delete it");
                    }
                }
            }
        } else {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Unsupported operation type %d for route entry",
                           msg_info.oper_type);
            return STD_ERR(MCAST, PARAM, 0);
        }
    } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_DEBUG("nas-mc-proc-hw",
                             "interface of ifindex %d is removed from all VLANs, all related entries will be deleted from npu",
                             msg_info.ifindex);
        } else {
            NAS_MC_LOG_DEBUG("nas-mc-proc-hw",
                             "interface of ifindex %d is removed from vlan %d, all related entries will be deleted from npu",
                             msg_info.ifindex, msg_info.vlan_id);
        }
        t_std_error rc = cache().delete_intf_entries(npu_port.npu_id,
                                                     msg_info.all_vlan, msg_info.vlan_id,
                                                     msg_info.ifindex);
        if (rc != STD_ERR_OK) {
            // Log the error info and return success to continue to cache flushing
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete entries: rc=%d", rc);
        }
    } else {
        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Unsupported message type %d", msg_info.msg_type);
        return STD_ERR(MCAST, PARAM, 0);
    }

    return STD_ERR_OK;
}

// Thread main function
static int nas_mc_proc_snooping_msg(void)
{
    mc_snooping_msg_t msg_info;
    while(true) {
        bool is_sync = false;
        pending_msg().wait_for_msg();
        while (pending_msg().pop(msg_info, is_sync)) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "\n%s\n", msg_info.dump_msg_info(is_sync).c_str());
            if (cache().update_needed(msg_info)) {
                t_std_error rc = STD_ERR_OK;
                // call ndi api to program multicast settings to npu
                if (msg_info.oper_type != mc_oper_type_t::STATUS) {
                    if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
                        cache().get_route_ndi_info(msg_info);

                    } else if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
                        cache().get_mrouter_ndi_info(msg_info);
                    }
                }
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Call NDI APIs to configure Multicast Entry to NPU");
                if ((rc = nas_mc_config_hw(msg_info)) != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to configure multicast on NPU, rc = %d", rc);
                }

                if (rc == STD_ERR_OK) {
                    cache().update(msg_info);
                }
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Cache is not needed or could not be updated");
            }
            if (is_sync) {
                pending_msg().proc_finish();
            }
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Multicast message processing done");
        }
    }

    return true;
}


static t_std_error create_default_groups(void)
{
    npu_id_t npu_max = static_cast<npu_id_t>(nas_switch_get_max_npus());
    t_std_error rc;
    ndi_obj_id_t group_id;
    for (npu_id_t npu = 0; npu < npu_max; npu ++) {
        rc = ndi_l2mc_group_create(npu, &group_id);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to create default multicast group for NPU %d", npu);
            return rc;
        }
        NAS_MC_LOG_INFO("NAS-MC-PROC-INIT", "Created default multicast group for NPU %d Grp Id = 0x%",PRIx64, npu,group_id);
        default_group_list[npu] = group_id;
    }
    return STD_ERR_OK;
}

static std_thread_create_param_t mc_msg_thr;

// Initiation
t_std_error nas_mc_proc_init(void)
{
    // Create default multicast group for each NPU
    if (create_default_groups() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-INIT", "Error creating default multicast group");
        return STD_ERR(MCAST, FAIL, 0);
    }
    // Start main thread
    std_thread_init_struct(&mc_msg_thr);
    mc_msg_thr.name = "mcast-snooping-msg";
    mc_msg_thr.thread_function = (std_thread_function_t)nas_mc_proc_snooping_msg;
    if (std_thread_create(&mc_msg_thr) !=  STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-INIT", "Error creating msg thread");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_INFO("NAS-MC-PROC-INIT", "Multicast message porcessing thread started");

    return STD_ERR_OK;
}
