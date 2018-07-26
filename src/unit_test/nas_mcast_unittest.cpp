/*
 * Copyright (c) 2017 Dell Inc.
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
 * filename: nas_mcast_unittest.cpp
 */

#include "gtest/gtest.h"

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "cps_api_events.h"
#include "nas_types.h"
#include "dell-base-acl.h"
#include "dell-base-if.h"
#include "dell-base-if-vlan.h"
#include "dell-interface.h"
#include "ietf-igmp-mld-snooping.h"
#include "l2-multicast.h"
#include "std_ip_utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <stdio.h>
#include <arpa/inet.h>

using namespace std;

static const uint_t TEST_VID = 100;
static const string ROUTE_IF_NAME_1{"e101-001-0"};
static const string ROUTE_IF_NAME_2{"e101-005-0"};
static const string ROUTE_LAG_IF_NAME{"bond9"};
static const string LAG_IF_NAME_1{"e101-003-0"};
static const string LAG_IF_NAME_2{"e101-004-0"};
static vector<string> TEST_NULL_LIST = {};
static vector<string> TEST_GRP_IPV4 = {"228.0.0.8"};
static vector<string> TEST_SRC_IPV4 = {"8.8.8.8"};
static vector<string> TEST_GRP_IPV6 = {"ff0e::8888"};
static vector<string> TEST_SRC_IPV6 = {"8888::8888"};
static vector<string> TEST_GRP_IPV4_LIST = {"225.0.0.5", "225.0.0.6", "225.0.0.7"};
static vector<string> TEST_SRC_IPV4_LIST = {"5.5.5.5", "6.6.6.6", "7.7.7.7"};
static vector<string> TEST_GRP_IPV6_LIST = {"ff0e::5", "ff0e::6", "ff0e::7"};
static vector<string> TEST_SRC_IPV6_LIST = {"5555::5555", "6666::6666", "7777::7777"};
static const string IGMP_MROUTER_IF_NAME{"e101-010-0"};
static const string MLD_MROUTER_IF_NAME{"e101-011-0"};
static const uint_t IGMP_PROTO_ID = 2;
static const string L2VLAN_TYPE{"ianaift:l2vlan"};
static const string LAG_TYPE{"ianaift:ieee8023adLag"};

// Get all ACL tables that contain IP_PROTOCOL and OUTER_VLAN_ID types
// in its allowered filters list
static bool get_acl_tables(vector<nas_obj_id_t>& tbl_id_list, bool chk_vlan)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         BASE_ACL_TABLE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }

    cps_api_object_t obj;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            obj = cps_api_object_list_get(gp.list, ix);
            cps_api_object_attr_t id_attr = cps_api_get_key_data(obj,
                                                    BASE_ACL_TABLE_ID);
            cps_api_object_attr_t stage_attr = cps_api_object_attr_get(obj,
                                                    BASE_ACL_TABLE_STAGE);
            if (id_attr == nullptr || stage_attr == nullptr) {
                cout << "ACL table object doesn't contian ID or stage attribute" << endl;
                continue;
            }
            BASE_ACL_STAGE_t stage =
                    static_cast<BASE_ACL_STAGE_t>(cps_api_object_attr_data_u32(stage_attr));
            if (stage != BASE_ACL_STAGE_INGRESS) {
                continue;
            }
            cps_api_object_it_t it;
            cps_api_object_it_begin(obj, &it);
            bool proto_flt_found = false, vlan_flt_found = false;
            while(cps_api_object_it_attr_walk(&it,
                                BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS)) {
                BASE_ACL_MATCH_TYPE_t match_type =
                    static_cast<BASE_ACL_MATCH_TYPE_t>(cps_api_object_attr_data_u32(it.attr));
                if (match_type == BASE_ACL_MATCH_TYPE_IP_PROTOCOL) {
                    proto_flt_found = true;
                } else if (match_type == BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID) {
                    vlan_flt_found = true;
                }
                if ((chk_vlan && proto_flt_found && vlan_flt_found) |
                    (!chk_vlan && proto_flt_found)) {
                    tbl_id_list.push_back(cps_api_object_attr_data_u64(id_attr));
                    break;
                }
                cps_api_object_it_next(&it);
            }
        }
    }

    cps_api_get_request_close(&gp);
    return true;
}

template<typename T>
static T get_attr_data_value(cps_api_object_attr_t attr)
{
    T data;

    if (is_same<T, uint8_t>::value) {
        data = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
    } else if (is_same<T, uint16_t>::value) {
        data = cps_api_object_attr_data_u16(attr);
    } else if (is_same<T, uint32_t>::value) {
        data = cps_api_object_attr_data_u32(attr);
    } else if (is_same<T, uint64_t>::value) {
        data = cps_api_object_attr_data_u64(attr);
    } else {
        return static_cast<T>(0);
    }

    return data;
}

template<typename T>
static bool check_embedded_value(cps_api_object_attr_t attr,
                                 cps_api_attr_id_t data_id,
                                 cps_api_attr_id_t mask_id, T chk_val)
{
    cps_api_object_it_t sub_it;
    cps_api_object_it_from_attr(attr, &sub_it);
    cps_api_object_it_inside(&sub_it);
    auto data_attr = cps_api_object_it_find(&sub_it, data_id);
    if (data_attr == nullptr) {
        return false;
    }
    auto mask_attr = cps_api_object_it_find(&sub_it, mask_id);
    T data, mask = static_cast<T>(-1);
    data = get_attr_data_value<T>(data_attr);
    if (mask_attr != nullptr) {
        mask = get_attr_data_value<T>(mask_attr);
    }

    return (data & mask) == (chk_val & mask);
}

// An ACl entry was considered as IGMP Lifting rule if:
// 1. Contains one filter type IP_PROTOCOL with value 2 (IGMP)
// 2. Optionally contains filter type OUTER_VLAN_ID with value of specified VID
// 3. Contains no filter other than above
// 4. Contains ACL action type TRAP_TO_CPU
static bool check_acl_entry(cps_api_object_t entry_obj, bool chk_vlan, uint_t vid)
{
    cps_api_object_attr_t attr;
    cps_api_object_it_t attr_it;
    attr = cps_api_object_attr_get(entry_obj, BASE_ACL_ENTRY_MATCH);
    if (attr == nullptr) {
        cout << "Entry match attribute not exist" << endl;
        return false;
    }
    cps_api_object_it_from_attr(attr, &attr_it);
    bool proto_flt = false;
    bool vlan_flt = false;
    for (cps_api_object_it_inside(&attr_it);
         cps_api_object_it_valid(&attr_it);
         cps_api_object_it_next(&attr_it)) {
        cps_api_object_it_t match_it = attr_it;
        cps_api_object_it_inside(&match_it);
        attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_TYPE);
        if (attr == nullptr) {
            cout << "Entry match type attribute not exist" << endl;
            return false;
        }
        BASE_ACL_MATCH_TYPE_t match_type =
            static_cast<BASE_ACL_MATCH_TYPE_t>(cps_api_object_attr_data_u32(attr));
        if (match_type == BASE_ACL_MATCH_TYPE_IP_PROTOCOL) {
            attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE);
            if (attr == nullptr) {
                cout << "IP protocol value attribute not exist" << endl;
                return false;
            }
            if (!check_embedded_value(attr,
                                      BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_DATA,
                                      BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_MASK,
                                      static_cast<uint8_t>(IGMP_PROTO_ID))) {
                return false;
            }
            proto_flt = true;
        } else if (match_type == BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID && chk_vlan) {
            attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE);
            if (attr == nullptr) {
                cout << "Outer VLAN ID value attribute not exist" << endl;
                return false;
            }
            if (!check_embedded_value(attr,
                                      BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_DATA,
                                      BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_MASK,
                                      static_cast<uint16_t>(vid))) {
                return false;
            }
            vlan_flt = true;
        } else {
            return false;
        }
    }

    if (!proto_flt || (chk_vlan && !vlan_flt)) {
        return false;
    }

    attr = cps_api_object_attr_get(entry_obj, BASE_ACL_ENTRY_ACTION);
    if (attr == nullptr) {
        return false;
    }
    cps_api_object_it_from_attr(attr, &attr_it);

    for (cps_api_object_it_inside(&attr_it);
         cps_api_object_it_valid(&attr_it);
         cps_api_object_it_next(&attr_it)) {
        cps_api_object_it_t action_it = attr_it;
        cps_api_object_it_inside(&action_it);
        attr = cps_api_object_it_find(&action_it, BASE_ACL_ENTRY_ACTION_TYPE);
        if (attr == nullptr) {
            cout << "Action type attribute not exist" << endl;
            return false;
        }
        BASE_ACL_ACTION_TYPE_t action_type =
            static_cast<BASE_ACL_ACTION_TYPE_t>(cps_api_object_attr_data_u32(attr));
        if (action_type == BASE_ACL_ACTION_TYPE_PACKET_ACTION) {
            attr = cps_api_object_it_find(&action_it, BASE_ACL_ENTRY_ACTION_PACKET_ACTION_VALUE);
            if (attr == nullptr) {
                cout << "Packet action value not exist" << endl;
                return false;
            }
            BASE_ACL_PACKET_ACTION_TYPE_t act_type =
                static_cast<BASE_ACL_PACKET_ACTION_TYPE_t>(cps_api_object_attr_data_u32(attr));
            if (act_type == BASE_ACL_PACKET_ACTION_TYPE_TRAP_TO_CPU) {
                return true;
            }
        }

    }

    return false;
}

static bool check_igmp_lift_rule(nas_obj_id_t table_id, bool chk_vlan, hal_vlan_id_t vid,
                                 bool& rule_found)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        return false;
    }

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         BASE_ACL_ENTRY_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_set_key_data(flt_obj, BASE_ACL_ENTRY_TABLE_ID,
                         cps_api_object_ATTR_T_U64,
                         &table_id, sizeof(uint64_t));

    rule_found = false;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            auto obj = cps_api_object_list_get(gp.list, ix);
            if (check_acl_entry(obj, chk_vlan, vid)) {
                rule_found = true;
                break;
            }
        }
    }

    cps_api_get_request_close(&gp);
    return true;
}

static bool check_vlan_exists(hal_vlan_id_t vlan_id, string& br_name)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }
    cps_api_get_request_guard grg(&gp);

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    cps_api_object_attr_add(flt_obj, IF_INTERFACES_INTERFACE_TYPE,
                            L2VLAN_TYPE.c_str(), L2VLAN_TYPE.size() + 1);

    cps_api_object_t obj;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            obj = cps_api_object_list_get(gp.list, ix);
            auto vid_attr = cps_api_get_key_data(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
            if (vid_attr == nullptr) {
                cout << "VID attribute not exist in VLAN object" << endl;
                continue;
            }
            hal_vlan_id_t vid = cps_api_object_attr_data_u16(vid_attr);
            if (vid == vlan_id) {
                auto name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
                if (name_attr == nullptr) {
                    cout << "Name attribute not exist in VLAN object, vid=" << vid << endl;
                    continue;
                }
                br_name = (char *)cps_api_object_attr_data_bin(name_attr);
                return true;
            }
        }
    }

    return false;
}

enum class intf_type
{
    LAG,
    VLAN
};

enum class oper_type
{
    CREATE,
    SET_MEMBER,
    DELETE
};

static bool set_vlan_or_lag_with_member(intf_type type, const string& name,
                                        const vector<string>& mbr_list,
                                        oper_type op, hal_vlan_id_t vlan_id = 0)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps transaction object" << endl;
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        cout << "Failed to create cps object" << endl;
        return false;
    }
    cps_api_object_guard obj_g(obj);
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         DELL_BASE_IF_CMN_SET_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    if (op == oper_type::CREATE) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_CREATE);
        if (type == intf_type::VLAN) {
            cps_api_object_attr_add_u16(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID, vlan_id);
            cps_api_object_attr_add_u32(obj, DELL_IF_IF_INTERFACES_INTERFACE_VLAN_TYPE,
                                        BASE_IF_VLAN_TYPE_DATA);
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_TYPE, L2VLAN_TYPE.c_str(),
                                    L2VLAN_TYPE.size() + 1);
        } else {
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME,
                                    name.c_str(), name.size() + 1);
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_TYPE, LAG_TYPE.c_str(),
                                    LAG_TYPE.size() + 1);
        }

    } else if (op == oper_type::SET_MEMBER) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_UPDATE);
    } else if (op == oper_type::DELETE) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_DELETE);
    } else {
        return false;
    }

    if (op == oper_type::SET_MEMBER || op == oper_type::DELETE) {
        cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME,
                                name.c_str(), name.size() + 1);
    }

    if (!mbr_list.empty()) {
        cps_api_attr_id_t list_index = 0;
        cps_api_attr_id_t lag_ids[3] = {DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS};
        for (auto& if_name: mbr_list) {
            if (type == intf_type::VLAN) {
                cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
                                        if_name.c_str(), if_name.size() + 1);
            } else {
                lag_ids[1] = list_index;
                lag_ids[2] = DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME;
                cps_api_object_e_add(obj, lag_ids, 3, cps_api_object_ATTR_T_BIN,
                                     if_name.c_str(), if_name.size() + 1);
                list_index ++;
            }
        }
    }

    obj_g.release();
    cps_api_transaction_guard tgd(&trans);
    cps_api_action(&trans, obj);
    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        return false;
    }

    return true;
}

static bool check_vlan_member_exists(const string br_name, const string& if_name)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }
    cps_api_get_request_guard grg(&gp);

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    cps_api_object_attr_add(flt_obj, IF_INTERFACES_INTERFACE_NAME,
                            if_name.c_str(), if_name.size() + 1);

    if (cps_api_get(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to read VLAN object" << endl;
        return false;
    }

    size_t mx = cps_api_object_list_size(gp.list);
    if (mx == 0) {
        cout << "No VLAN object returned for bridge " << if_name << endl;
        return false;
    }
    auto obj = cps_api_object_list_get(gp.list, 0);
    cps_api_object_it_t it;
    for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        auto attr_id = cps_api_object_attr_id(it.attr);
        if (attr_id == DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS ||
            attr_id == DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS) {
            string mbr_if_name = (char *)cps_api_object_attr_data_bin(it.attr);
            if (mbr_if_name == if_name) {
                return true;
            }
        }
    }

    return false;
}

static cps_api_event_service_handle_t evt_handle;
static bool evt_service_inited = false;

static bool event_service_init()
{
    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        return false;
    }
    if (cps_api_event_client_connect(&evt_handle) != cps_api_ret_code_OK) {
        return false;
    }
    evt_service_inited = true;
    return true;
}

static bool event_service_deinit()
{
    if (!evt_service_inited) {
        return true;
    }
    evt_service_inited = false;
    return (cps_api_event_client_disconnect(evt_handle) == cps_api_ret_code_OK);
}

static bool send_mc_update_event(hal_vlan_id_t vlan_id, const string& if_name,
                                 vector<string> &group_ip,
                                 vector<string> &src_ip,
                                 bool ipv4, bool mrouter, bool add)
{
    bool event_start_internal;
    if (!evt_service_inited) {
        if (!event_service_init()) {
            cout << "Failed to start event service" << endl;
            return false;
        }
        event_start_internal = true;
    } else {
        event_start_internal = false;
    }
    bool ret_val = false;
    do {
        cps_api_object_t obj = cps_api_object_create();
        if (obj == nullptr) {
            cout << "Failed to create cps object" << endl;
            break;
        }
        cps_api_attr_id_t key_id, vlan_attr_id, mr_if_attr_id, rt_if_attr_id, grp_id, gip_attr_id, src_id, srcip_attr_id;
        if (ipv4) {
            key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN;
            vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
            mr_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
            rt_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
            grp_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;
            gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
            src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
            srcip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        } else {
            key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN;
            vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
            mr_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
            rt_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
            grp_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;
            gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
            src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
            srcip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        }
        cps_api_object_guard og(obj);
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), key_id,
                        cps_api_qualifier_OBSERVED)) {
            cout << "Failed to initiate object key" << endl;
            break;
        }
        cps_api_object_set_type_operation(cps_api_object_key(obj),
                                          add ? cps_api_oper_CREATE : cps_api_oper_DELETE);
        cps_api_object_attr_add_u16(obj, vlan_attr_id, vlan_id);
        if (mrouter) {
            if (!cps_api_object_attr_add(obj, mr_if_attr_id, if_name.c_str(), if_name.size() + 1)) {
                cout << "Failed to set mrouter interface name" << endl;
                break;
            }
        } else {
            for (cps_api_attr_id_t g = 0; g < group_ip.size();g++) {
                cps_api_attr_id_t ids[3] = {grp_id, g, rt_if_attr_id};
                if (if_name.length() > 0) {
                    if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, if_name.c_str(), if_name.size() + 1)) {
                        cout << "Failed to set mc entry interface name" << endl;
                        break;
                    }
                }
                ids[2] = gip_attr_id;
                if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, group_ip[g].c_str(), group_ip[g].size() + 1)) {
                    cout << "Failed to set mc entry group IP address" << endl;
                    break;
                }
                for (cps_api_attr_id_t i = 0; i < src_ip.size();i++) {
                    cps_api_attr_id_t srcip_ids[5] = {grp_id, g, src_id, i,srcip_attr_id};
                    if (!cps_api_object_e_add(obj, srcip_ids, 5, cps_api_object_ATTR_T_BIN, src_ip[i].c_str(), src_ip[i].size() + 1)) {
                        cout << "Failed to set mc entry src IP address" << endl;
                        break;
                    }
                }
            }
        }
        if (cps_api_event_publish(evt_handle, obj) != cps_api_ret_code_OK) {
            cout << "Failed to publish event" << endl;
            break;
        }
        ret_val = true;
    } while(0);

    sleep(1);

    if (event_start_internal) {
        event_service_deinit();
    }

    return ret_val;
}

static bool is_ipv4_addr(const string& ip_addr)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip_addr.c_str(), &addr);
}

static bool is_ipv6_addr(const string& ip_addr)
{
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip_addr.c_str(), &addr);
}

struct igmp_mld_entry
{
    hal_vlan_id_t vlan_id;
    hal_ip_addr_t src_ip;
    hal_ip_addr_t mc_ip;
    uint32_t group_id;
    vector<string> port_list;
};

enum class line_mark_t
{
    NONE,
    START,
    END,
};

using line_check_func_t = function<line_mark_t(string)>;
using handler_func_t = function<bool(const vector<string>&, vector<igmp_mld_entry>&)>;

static line_mark_t igmp_entry_check(const string& line)
{
    istringstream iss(line);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 9) {
        return line_mark_t::NONE;
    }
    if (!is_ipv4_addr(tokens[0]) || !is_ipv4_addr(tokens[1])) {
        return line_mark_t::NONE;
    }

    return line_mark_t::START;
}

static bool igmp_entry_proc(const vector<string>& line_list, vector<igmp_mld_entry>& entry_list)
{
    if (line_list.empty()) {
        return false;
    }
    istringstream iss(line_list[0]);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    igmp_mld_entry igmp_entry;
    if (!std_str_to_ip(tokens[0].c_str(), &igmp_entry.src_ip)) {
        cout << "Invalid source IP: " << tokens[0] << endl;
        return false;
    }
    if (!std_str_to_ip(tokens[1].c_str(), &igmp_entry.mc_ip)) {
        cout << "Invalid multicast IP: " << tokens[1] << endl;
        return false;
    }

    igmp_entry.vlan_id = stoi(tokens[2]);
    igmp_entry.group_id = stoul(tokens[8], 0, 16);
    entry_list.push_back(igmp_entry);

    return true;
}

static line_mark_t mld_entry_check(const string& line)
{
    const string start_tag = "SRC IP ADDRESS: ";
    if (line.compare(0, start_tag.size(), start_tag) == 0) {
        return line_mark_t::START;
    }
    return line_mark_t::NONE;
}

static void right_trim(string& in_str)
{
    string t{" \t\n\r"};
    in_str.erase(in_str.find_last_not_of(t) + 1);
}

static bool mld_entry_proc(const vector<string>& line_list, vector<igmp_mld_entry>& entry_list)
{
    const string src_ip_tag = "SRC IP ADDRESS: ";
    const string mc_ip_tag = "MC  IP ADDRESS: ";
    if (line_list.size() < 4) {
        cout << "Invalid line count for MLD entry" << endl;
        return false;
    }

    igmp_mld_entry igmp_entry;
    if (line_list[0].compare(0, src_ip_tag.size(), src_ip_tag) != 0) {
        cout << "Invalid line format: " << line_list[0] << endl;
        return false;
    }
    auto src_ip_str = line_list[0].substr(src_ip_tag.size());
    right_trim(src_ip_str);
    if (!is_ipv6_addr(src_ip_str)) {
        cout << "Invalid ipv6 address: " << src_ip_str << endl;
        return false;
    }
    if (!std_str_to_ip(src_ip_str.c_str(), &igmp_entry.src_ip)) {
        return false;
    }
    auto mc_ip_str = line_list[1].substr(mc_ip_tag.size());
    right_trim(mc_ip_str);
    if (!is_ipv6_addr(mc_ip_str)) {
        cout << "Invalid ipv6 address: " << mc_ip_str << endl;
        return false;
    }
    if (!std_str_to_ip(mc_ip_str.c_str(), &igmp_entry.mc_ip)) {
        return false;
    }
    istringstream iss(line_list[3]);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 7) {
        return false;
    }
    igmp_entry.vlan_id = stoi(tokens[0]);
    igmp_entry.group_id = stoul(tokens[6], 0, 16);
    entry_list.push_back(igmp_entry);

    return true;
}

static line_mark_t mc_group_check(const string& line)
{
    const string start_tag = "Group ";
    if (line.compare(0, start_tag.size(), start_tag) == 0) {
        return line_mark_t::START;
    }
    return line_mark_t::NONE;
}

static bool mc_group_proc(const vector<string>& line_list, vector<igmp_mld_entry>& entry_list)
{
    if (line_list.empty()) {
        return false;
    }
    istringstream iss{line_list[0]};
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 3) {
        return false;
    }
    uint32_t group_id = stoul(tokens[1], 0, 16);
    vector<string> port_list;

    for (size_t idx = 1; idx < line_list.size(); idx ++) {
        istringstream iss{line_list[idx]};
        vector<string> tokens{istream_iterator<string>{iss}, {}};
        if (tokens.size() < 2) {
            continue;
        }
        auto port_name = tokens[1];
        if (port_name.back() == ',') {
            port_name.erase(port_name.size() - 1);
        }
        port_list.push_back(port_name);
    }

    if (!port_list.empty()) {
        for (auto& entry: entry_list) {
            if (entry.group_id == group_id) {
                entry.port_list.insert(entry.port_list.end(), port_list.begin(), port_list.end());
            }
        }
    }

    return true;
}

static vector<igmp_mld_entry> mc_entry_list;

static bool run_command(const string& cmd, line_check_func_t check_func, handler_func_t proc_func)
{
    FILE *fp = popen(cmd.c_str(), "r");
    char lnbuf[512];
    if (fp == nullptr) {
        cout << "Failed to open file to run command" << endl;
        return false;
    }

    bool started = false;
    vector<string> line_buf;
    string s;
    while(fgets(lnbuf, 512, fp)) {
        s = string{lnbuf};
        auto ret_val = check_func(s);
        if (started) {
            if (ret_val == line_mark_t::NONE) {
                line_buf.push_back(s);
                continue;
            }
            if (ret_val == line_mark_t::END) {
                line_buf.push_back(s);
                started = false;
            }
            if (!proc_func(line_buf, mc_entry_list)) {
                cout << "Failed to process mcast entry" << endl;
                pclose(fp);
                return false;
            }
            line_buf.clear();
            if (ret_val == line_mark_t::START) {
                line_buf.push_back(s);
            }
        } else {
            if (ret_val == line_mark_t::NONE) {
                continue;
            } else if (ret_val == line_mark_t::START) {
                line_buf.push_back(s);
                started = true;
            } else {
                cout << "Invalid line format" << endl;
                continue;
            }
        }
    }
    if (started) {
        if (!proc_func(line_buf, mc_entry_list)) {
            cout << "Failed to process mcast entry" << endl;
            pclose(fp);
            return false;
        }
    }
    pclose(fp);
    return true;
}

static void dump_mc_entry_list()
{
    char ip_buf[512];
    for (auto& entry: mc_entry_list) {
        cout << "--------- multicast entry ---------" << endl;
        cout << "  VLAN ID      : " << entry.vlan_id << endl;
        cout << "  Source IP    : " << std_ip_to_string(&entry.src_ip, ip_buf, 512) << endl;
        cout << "  MC IP        : " << std_ip_to_string(&entry.mc_ip, ip_buf, 512) << endl;
        cout << "  Group ID     : " << hex << entry.group_id << dec << endl;
        cout << "  Member Ports : ";
        for (auto port: entry.port_list) {
            cout << port << " ";
        }
        cout << endl;
        cout << "-----------------------------------" << endl;
    }
}

static void cleanup_intf_l2mc_config(hal_vlan_id_t vlan_id, const string& if_name)
{
    cps_api_transaction_params_t params;
    cps_api_object_t             obj;
    cps_api_key_t                keys;

    ASSERT_TRUE((obj = cps_api_object_create()) != NULL);
    cps_api_object_guard obj_g (obj);
    ASSERT_TRUE(cps_api_transaction_init(&params) == cps_api_ret_code_OK);

    cps_api_transaction_guard tgd(&params);
    cps_api_key_from_attr_with_qual(&keys, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj, &keys);
    cps_api_object_attr_add(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFNAME,
                            if_name.c_str(), if_name.length() + 1);
    cps_api_object_attr_add_u32(obj,  BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID, vlan_id);

    ASSERT_TRUE(cps_api_action(&params, obj) == cps_api_ret_code_OK);

    obj_g.release();
    ASSERT_TRUE(cps_api_commit(&params) == cps_api_ret_code_OK);
}

// match: igmp, action: trap_to_cpu
TEST(nas_mc, acl_rule_check)
{
    bool chk_vlan = true;
    vector<nas_obj_id_t> chk_table_ids{};
    ASSERT_TRUE(get_acl_tables(chk_table_ids, chk_vlan));
    bool found = false;
    for (auto table_id: chk_table_ids) {
        cout << "Checking on ACL table: " << table_id << endl;
        ASSERT_TRUE(check_igmp_lift_rule(table_id, chk_vlan, TEST_VID, found));
        if (found) {
            cout << "Found ACL rule to lift IGMP packets of VLAN " << TEST_VID << endl;
            break;
        }
    }
    if (!found && chk_vlan) {
        chk_vlan = false;
        cout << "Could not find table with VLAN and IP_PROTOCOl filters" << endl;
        cout << "Try to search for table with IP_PROTOCOL filter only" << endl;
        chk_table_ids.clear();
        ASSERT_TRUE(get_acl_tables(chk_table_ids, chk_vlan));
        for (auto table_id: chk_table_ids) {
            cout << "Checking on ACL table: " << table_id << endl;
            ASSERT_TRUE(check_igmp_lift_rule(table_id, chk_vlan, 0, found));
            if (found) {
                cout << "Found ACL rule to lift IGMP packets of all VLANs" << endl;
                break;
            }
        }
    }

    // ASSERT_TRUE(found);
}

TEST(nas_mc, create_lag_and_member)
{
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME,
                                            {LAG_IF_NAME_1, LAG_IF_NAME_2},
                                            oper_type::CREATE));
}

TEST(nas_mc, create_vlan_and_member)
{
    string br_name{};
    vector<string> member_list{ROUTE_IF_NAME_1, ROUTE_IF_NAME_2, IGMP_MROUTER_IF_NAME, MLD_MROUTER_IF_NAME,ROUTE_LAG_IF_NAME};
    if (!check_vlan_exists(TEST_VID, br_name)) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, {},
                                                member_list,
                                                oper_type::CREATE, TEST_VID));
        ASSERT_TRUE(check_vlan_exists(TEST_VID, br_name));
        cout << "VLAN bridge " << br_name << " is created" << endl;
        return;
    }
    for (auto& br_if: member_list) {
        if (!check_vlan_member_exists(br_name, br_if)) {
            ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, {br_if},
                                                    oper_type::SET_MEMBER));
        }
    }
}

TEST(nas_mc, init_event_service)
{
    ASSERT_TRUE(event_service_init());
}

TEST(nas_mc, send_mrouter_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc, send_ipv4_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
}

TEST(nas_mc, send_ipv6_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
}

TEST(nas_mc, validate_igmp_entry)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(!entry.port_list.empty());
    }
}

TEST(nas_mc, validate_mld_entry)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(!entry.port_list.empty());
    }
}

TEST(nas_mc, send_ipv4_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
}

TEST(nas_mc, send_ipv6_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
}

TEST(nas_mc, send_mrouter_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

// Test on non-OIF multicast routing configuration

TEST(nas_mc, send_ipv4_non_oif_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
}

TEST(nas_mc, send_ipv6_non_oif_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
}

// All entries created should not link to group with member ports

TEST(nas_mc, validate_igmp_non_oif_entry)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }
}

TEST(nas_mc, validate_mld_non_oif_entry)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }
}

// Add mrouter port to make non-OIF entry not use default group

TEST(nas_mc, send_mrouter_add_event_1)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

// Non-OIF entries should link to group with mrouter port members

TEST(nas_mc, validate_igmp_entry_1)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(!entry.port_list.empty());
    }
}

TEST(nas_mc, validate_mld_entry_1)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(!entry.port_list.empty());
    }
}

// Delete mrouter port to make non-OIF entry use default group again

TEST(nas_mc, send_mrouter_del_event_1)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

// Non-OIF entries should be changed back to link to group with no port member

TEST(nas_mc, validate_igmp_non_oif_entry_1)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }
}

TEST(nas_mc, validate_mld_non_oif_entry_1)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(mc_entry_list.size() > 0);
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }
}

TEST(nas_mc, send_ipv4_non_oif_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
}

TEST(nas_mc, send_ipv6_non_oif_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
}

TEST(nas_mc, check_clear_intf_entries)
{
    // Create non-OIF entry
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6, TEST_NULL_LIST, false, false, true));
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    cout << "Non-OIF entries for IPv4 and IPv6 group addresses:" << endl;
    dump_mc_entry_list();
    ASSERT_TRUE(mc_entry_list.size() == 2);
    ASSERT_TRUE(mc_entry_list[0].group_id == mc_entry_list[1].group_id);
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }
    auto dft_group_id = mc_entry_list[0].group_id;

    // Add mrouter
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    cout << "After mrouter interfaces being added:" << endl;
    dump_mc_entry_list();
    ASSERT_TRUE(mc_entry_list.size() == 2);
    ASSERT_TRUE(mc_entry_list[0].group_id != dft_group_id);
    ASSERT_TRUE(mc_entry_list[1].group_id != dft_group_id);
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(!entry.port_list.empty());
    }

    // Clear intf entries
    cout << "Clear entries for interface " << IGMP_MROUTER_IF_NAME << " and " << MLD_MROUTER_IF_NAME << endl;
    cleanup_intf_l2mc_config(TEST_VID, IGMP_MROUTER_IF_NAME);
    cleanup_intf_l2mc_config(TEST_VID, MLD_MROUTER_IF_NAME);
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    cout << "After mrouter interface related entries being deleted:" << endl;
    dump_mc_entry_list();
    ASSERT_TRUE(mc_entry_list.size() == 2);
    ASSERT_TRUE(mc_entry_list[0].group_id == dft_group_id);
    ASSERT_TRUE(mc_entry_list[1].group_id == dft_group_id);
    for (auto& entry: mc_entry_list) {
        ASSERT_TRUE(entry.port_list.empty());
    }

    // Delete entries
    cout << "Delete all entries" << endl;
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6, TEST_NULL_LIST, false, false, false));
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    ASSERT_TRUE(mc_entry_list.empty());
}

TEST(nas_mc, deinit_event_service)
{
    ASSERT_TRUE(event_service_deinit());
}

TEST(nas_mc, delete_vlan)
{
    string br_name{};
    if (check_vlan_exists(TEST_VID, br_name)) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, {}, oper_type::DELETE));
    }
}

TEST(nas_mc, delete_lag)
{
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME,
                {LAG_IF_NAME_1, LAG_IF_NAME_2}, oper_type::DELETE));
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME, {}, oper_type::DELETE));
}

int main(int argc, char *argv[])

{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
