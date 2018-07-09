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
 * filename: nas_mc_cps.cpp
 */

#include "nas_mc_util.h"
#include "cps_api_events.h"
#include "hal_if_mapping.h"
#include "ietf-igmp-mld-snooping.h"
#include "l2-multicast.h"
#include "std_utils.h"
#include "std_ip_utils.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"

#include <inttypes.h>
#include <vector>

static cps_api_key_t mc_igmp_obj_key;
static cps_api_key_t mc_mld_obj_key;

#define KEY_PRINT_BUF_LEN 100

static hal_ip_addr_t ipv4_null_ip;
static hal_ip_addr_t ipv6_null_ip;

// Convert interface name to ifindex
static t_std_error nas_mc_name_to_ifindex(const char *if_name, hal_ifindex_t& ifindex)
{
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, if_name, sizeof(intf_ctrl.if_name));

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return STD_ERR(MCAST, FAIL, 0);
    }

    ifindex = intf_ctrl.if_index;
    return STD_ERR_OK;
}

static bool nas_mc_mrouter_handler(mc_event_type_t evt_type, hal_vlan_id_t vid, bool add,
                                   const cps_api_object_it_t& itor)
{
    const char *if_name = (char *)cps_api_object_attr_data_bin(itor.attr);
    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Mrouter interface %s", if_name);
    hal_ifindex_t ifindex = 0;
    if (nas_mc_name_to_ifindex(if_name, ifindex) != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to get ifindex from if name");
        return false;
    }
    NAS_MC_LOG_INFO("NAS-MC-CPS", "%s multicast router interface %d, VID=%d",
                     add ? "Add" : "Delete", ifindex, vid);
    if (add) {
        nas_mc_add_mrouter(evt_type, vid, ifindex);
    } else {
        nas_mc_del_mrouter(evt_type, vid, ifindex);
    }
    return true;
}

static bool nas_mc_route_handler(mc_event_type_t evt_type, hal_vlan_id_t vid, bool add,
                                 const cps_api_object_it_t& itor)
{
    hal_ip_addr_t group_ip;
    hal_ip_addr_t source_ip;
    hal_ifindex_t ifindex = 0;
    cps_api_attr_id_t group_addr_id, group_src_id, group_src_addr_id;
    cps_api_attr_id_t group_if_id;

    if (evt_type == mc_event_type_t::IGMP) {
        group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
    } else if (evt_type == mc_event_type_t::MLD) {
        group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
    } else {
        return false;
    }

    std::vector<hal_ip_addr_t> src_ip_list = {};
    cps_api_object_it_t in_it = itor;
    cps_api_object_it_inside(&in_it);
    for (; cps_api_object_it_valid(&in_it); cps_api_object_it_next(&in_it)) {
        cps_api_attr_id_t list_index = cps_api_object_attr_id(in_it.attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast group item index: %lu", list_index);
        cps_api_object_it_t grp_it = in_it;
        cps_api_object_it_inside(&grp_it);
        bool addr_found = false, if_found = false;

        /* Clear source list from previous group */
        src_ip_list.clear();

        for(; cps_api_object_it_valid(&grp_it); cps_api_object_it_next(&grp_it)) {
            cps_api_attr_id_t grp_attr_id = cps_api_object_attr_id(grp_it.attr);
            NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Handling mc group attribute id %" PRIx64, grp_attr_id);
            if (grp_attr_id == group_if_id) {
                const char *if_name = (char *)cps_api_object_attr_data_bin(grp_it.attr);
                NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route interface %s", if_name);
                if (nas_mc_name_to_ifindex(if_name, ifindex) != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to get ifindex from if name");
                    return false;
                }
                if_found = true;
            } else if (grp_attr_id == group_addr_id) {
                const char *ip_addr_str = (const char *)cps_api_object_attr_data_bin(grp_it.attr);
                NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route group address %s", ip_addr_str);
                memset(&group_ip, 0, sizeof(hal_ip_addr_t));
                if (!std_str_to_ip(ip_addr_str, &group_ip)) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to convert IP string to data");
                    return false;
                }
                if (!((evt_type == mc_event_type_t::IGMP && group_ip.af_index == HAL_INET4_FAMILY) ||
                      (evt_type == mc_event_type_t::MLD && group_ip.af_index == HAL_INET6_FAMILY))) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Protocol family of group IP not match");
                    return false;
                }
                addr_found = true;
            } else if (grp_attr_id == group_src_id) {
                cps_api_object_it_t in_grp_it = grp_it;
                cps_api_object_it_inside(&in_grp_it);
                for(; cps_api_object_it_valid(&in_grp_it); cps_api_object_it_next(&in_grp_it)) {
                    cps_api_attr_id_t src_index = cps_api_object_attr_id(in_grp_it.attr);
                    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast source item index: %lu", src_index);
                    cps_api_object_it_t src_it = in_grp_it;
                    cps_api_object_it_inside(&src_it);
                    for(; cps_api_object_it_valid(&src_it); cps_api_object_it_next(&src_it)) {
                        cps_api_attr_id_t src_attr_id = cps_api_object_attr_id(src_it.attr);
                        if (src_attr_id == group_src_addr_id) {
                            const char *src_ip_str = (const char *)cps_api_object_attr_data_bin(src_it.attr);
                            NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route group source address %s", src_ip_str);
                            memset(&source_ip, 0, sizeof(hal_ip_addr_t));
                            if (!std_str_to_ip(src_ip_str, &source_ip)) {
                                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to convert source IP string to data");
                                return false;
                            }
                            if (!((evt_type == mc_event_type_t::IGMP && source_ip.af_index == HAL_INET4_FAMILY) ||
                                  (evt_type == mc_event_type_t::MLD && source_ip.af_index == HAL_INET6_FAMILY))) {
                                NAS_MC_LOG_ERR("NAS-MC-CPS", "Protocol family of group source IP not match");
                                return false;
                            }
                            src_ip_list.push_back(source_ip);
                        }
                    }
                }
            }
        }
        if (!addr_found) {
            NAS_MC_LOG_ERR("NAS-MC-CPS", "Could not find mandatory attribute GROUP_IP");
            return false;
        }
        bool is_xg = src_ip_list.empty();
        if (is_xg) {
            if (evt_type == mc_event_type_t::IGMP) {
                src_ip_list.push_back(ipv4_null_ip);
            } else {
                src_ip_list.push_back(ipv6_null_ip);
            }
        }
        for (auto& src_ip: src_ip_list) {
            char ip_buf[HAL_INET6_TEXT_LEN + 1];
            const char *ip_str = std_ip_to_string(&group_ip, ip_buf, sizeof(ip_buf));
            char src_ip_buf[HAL_INET6_TEXT_LEN + 1];
            const char *src_ip_str = std_ip_to_string(&src_ip, src_ip_buf, sizeof(src_ip_buf));
            NAS_MC_LOG_INFO("NAS-MC-CPS", "%s multicast route entry: VID %d IP %s SRC %s IF %d",
                             add ? "Add" : "Delete", vid, ip_str, src_ip_str, ifindex);
            if (add) {
                nas_mc_add_route(evt_type, vid, group_ip, is_xg, src_ip, if_found, ifindex);
            } else {
                nas_mc_del_route(evt_type, vid, group_ip, is_xg, src_ip, if_found, ifindex);
            }
        }
    }

    return true;
}

static bool nas_mc_event_handler(cps_api_object_t evt_obj, void *param)
{
    cps_api_object_attr_t vlan_id_attr;
    cps_api_object_attr_t status_attr;

    cps_api_attr_id_t mrouter_id;
    cps_api_attr_id_t group_id;

    mc_event_type_t evt_type;
    if (cps_api_key_matches(&mc_igmp_obj_key,
                    cps_api_object_key(evt_obj), true) == 0) {
        evt_type = mc_event_type_t::IGMP;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE);
    } else if (cps_api_key_matches(&mc_mld_obj_key,
                    cps_api_object_key(evt_obj), true) == 0) {
        evt_type = mc_event_type_t::MLD;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_ENABLE);
    } else {
        char key_buf[KEY_PRINT_BUF_LEN];
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Unsupported object key: %s",
                       cps_api_key_print(cps_api_object_key(evt_obj), key_buf, sizeof(key_buf)));
        return false;
    }

    if (vlan_id_attr == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "VLAN ID attribute not found");
        return false;
    }

    hal_vlan_id_t vid = cps_api_object_attr_data_u16(vlan_id_attr);

    if (status_attr != nullptr) {
        uint_t snp_status = cps_api_object_attr_data_u32(status_attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Setting Multicast snooping status %d",
                         snp_status);
        nas_mc_change_snooping_status(evt_type, vid, (bool)snp_status);
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(evt_obj));
    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "CPS Event received: VLAN_ID %d OPER_TYPE %d",
                     vid, op);

    bool is_add;
    if (op == cps_api_oper_CREATE) {
        is_add = true;
    } else if (op == cps_api_oper_DELETE) {
        is_add = false;
    } else {
        // Other operation type only for snooping status setting
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "No handling for operation set");
        return true;
    }

    cps_api_object_it_t it;
    for (cps_api_object_it_begin(evt_obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        cps_api_attr_id_t attr_id = cps_api_object_attr_id(it.attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Handling event object attribute id %" PRIx64, attr_id);
        if (attr_id == mrouter_id) {
            if (!nas_mc_mrouter_handler(evt_type, vid, is_add, it)) {
                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failure on handling mrouter message");
                return false;
            }
        } else if (attr_id == group_id) {
            if (!nas_mc_route_handler(evt_type, vid, is_add, it)) {
                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failure on handling mcast entry message");
                return false;
            }
        }
    }

    return true;
}

// Register event handler as thread
static t_std_error nas_mc_event_handle_reg(void)
{
    cps_api_event_reg_t reg;

    memset(&reg, 0, sizeof(reg));
    const uint_t NUM_KEYS = 2;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_from_attr_with_qual(&key[0],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_igmp_obj_key, &key[0], sizeof(cps_api_key_t));

    cps_api_key_from_attr_with_qual(&key[1],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_mld_obj_key, &key[1], sizeof(cps_api_key_t));

    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg, nas_mc_event_handler, NULL)
            != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to register on event handling thread");
        return STD_ERR(MCAST,FAIL,0);
    }
    return STD_ERR_OK;
}

#define NUM_MC_CPS_API_THREAD   1

static cps_api_operation_handle_t nas_mc_cps_handle;

static cps_api_return_code_t nas_mc_cleanup_handler(void *context,
                                            cps_api_transaction_params_t *param,
                                            size_t ix)
{
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP",
                     "Entering multicast snooping entries cleanup handler");
    if (param == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Invalid argument");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Cleanup object is not present at index %lu", ix);
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Invalid operation type %d", op);
        return cps_api_ret_code_ERR;
    }

    hal_ifindex_t ifindex = 0;
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj,
                                        BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFINDEX);
    if (attr == nullptr) {
        attr = cps_api_object_attr_get(obj,
                                BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFNAME);
        if (attr == nullptr) {
            attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID);
            if (attr == nullptr) {
                NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Either ifindex, ifname or vlan_id should be given");
                return cps_api_ret_code_ERR;
            }
            hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(attr);
            NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for VLAN %d", vlan_id);
            nas_mc_cleanup_vlan(vlan_id);
            return cps_api_ret_code_OK;
        }
        const char *ifname = static_cast<const char*>(cps_api_object_attr_data_bin(attr));
        t_std_error rc = nas_mc_name_to_ifindex(ifname, ifindex);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to get ifindex of interface %s, rc=%d",
                           ifname, rc);
            return rc;
        }
    } else {
        ifindex = cps_api_object_attr_data_u32(attr);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for interface with ifindex %d",
                     ifindex);

    attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID);
    if (attr == nullptr) {
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for all VLANs");
        nas_mc_cleanup_interface(ifindex);
    } else {
        hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for VLAN %d", vlan_id);
        nas_mc_cleanup_vlan_member(vlan_id, ifindex);
    }

    return cps_api_ret_code_OK;
}

static t_std_error nas_mc_cleanup_handle_reg(void)
{
    if (cps_api_operation_subsystem_init(&nas_mc_cps_handle, NUM_MC_CPS_API_THREAD) !=
        cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to initiate cps subsystem");
        return STD_ERR(MCAST, FAIL, 0);
    }

    cps_api_registration_functions_t f{};
    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to get object key");
        return STD_ERR(MCAST, FAIL, 0);
    }
    f.handle = nas_mc_cps_handle;
    f._write_function = nas_mc_cleanup_handler;
    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to register cps callback");
        return STD_ERR(MCAST, FAIL, 0);
    }

    return STD_ERR_OK;
}

t_std_error nas_mc_cps_init(void)
{
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "Initiating NAS multicast CPS serivce");

    // register event
    if (nas_mc_event_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to register event handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast event handling registered");

    // register rpc handler
    if (nas_mc_cleanup_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to register cleanup handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast cleanup handler registered");

    if (!std_str_to_ip("0.0.0.0", &ipv4_null_ip)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to convert NULL IPv4 string to data");
        memset(&ipv4_null_ip, 0, sizeof(ipv4_null_ip));
    }
    if (!std_str_to_ip("::", &ipv6_null_ip)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to convert NULL IPv6 string to data");
        memset(&ipv6_null_ip, 0, sizeof(ipv6_null_ip));
    }

    return STD_ERR_OK;
}
