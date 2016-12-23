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
 * filename: nas_mac_api.cpp
 */

#include "nas_mac_api.h"
#include "nas_switch.h"
#include "std_error_codes.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mac.h"
#include "nas_base_utils.h"
#include "nas_linux_l2.h"

#include <unordered_set>
#include <stdlib.h>

#define MAC_STRING_LEN 20

/*
 * global mac table instance
 */
static nas_mac_table_info nas_mac_table;

typedef struct mac_struct_t {

    mac_struct_t(){}

    mac_struct_t(hal_mac_addr_t addr){
        memcpy(mac_addr,addr,sizeof(hal_mac_addr_t));
    }

    uint8_t mac_addr[(sizeof(hal_mac_addr_t))];
    bool operator== (const mac_struct_t& rhs)  const
    {
        if (memcmp(mac_addr, rhs.mac_addr, HAL_MAC_ADDR_LEN)) return false;
        return true;
    }

} nas_mac_struct;

class mac_addr_hash
{
public:
    std::size_t operator() (nas_mac_struct const&s) const
    {
        static const size_t MAC_STR_BUFF=20;
        char mac_str[MAC_STR_BUFF] = {0};
        std::string mac_text = std_mac_to_string(&s.mac_addr, &mac_str[0], sizeof(mac_str));
        std::size_t mac_hash = std::hash<std::string>() (mac_text);
        return mac_hash;
    }
};
/*
 * map data structure to contain vlan to list of mac addresses
 */
typedef std::unordered_set<nas_mac_struct,mac_addr_hash> nas_mac_address_list_t;
typedef nas_mac_address_list_t::iterator it_nas_mac_address_list_t;

typedef std::unordered_map<hal_vlan_id_t, nas_mac_address_list_t> nas_vlan_to_mac_addr_map_t;
typedef nas_vlan_to_mac_addr_map_t::iterator it_vlan_to_addr_t;

static nas_vlan_to_mac_addr_map_t nas_vlan_to_mac_addr_map[2];

/*
 * map data structure to contain mac address to vlan list
 */
typedef std::unordered_set<hal_vlan_id_t> nas_vlan_list_t;
typedef nas_vlan_list_t::iterator it_nas_vlan_list_t;

typedef std::unordered_map<mac_struct_t, nas_vlan_list_t,mac_addr_hash> nas_mac_to_vlan_map_t;
typedef nas_mac_to_vlan_map_t::iterator it_mac_to_vlan_t;

static nas_mac_to_vlan_map_t nas_mac_to_vlan_map[2];

/*
 * map data structure to contain interface to mac/vlan list
 */
typedef std::unordered_set<nas_mac_entry_key,mac_entry_hash> nas_mac_vlan_list_t;
typedef nas_mac_vlan_list_t::iterator it_nas_mac_vlan_list_t;

typedef std::unordered_map<hal_ifindex_t, nas_mac_vlan_list_t> nas_intf_to_mac_vlan_map_t;
typedef nas_intf_to_mac_vlan_map_t::iterator it_intf_to_mac_vlan_t;

static nas_intf_to_mac_vlan_map_t nas_intf_to_mac_vlan_map[2];

/* returns an iterator into the mac-to-vlan map with a given mac address as the key */

static inline it_mac_to_vlan_t nas_get_it_mac_to_vlan (hal_mac_addr_t hal_mac,
                                         nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr) {
    return (mac_to_vlan_map_ptr->find(nas_mac_struct(hal_mac)));
}


bool nas_mac_table_info::add_mac_entry(const nas_mac_entry_t &entry, bool static_type) {

    nas_mac_entry_key key_pair;
    key_pair.vlan_id = entry.entry_key.vlan_id;
    memcpy(key_pair.mac_addr, entry.entry_key.mac_addr, sizeof(hal_mac_addr_t));

    try {
        if (static_type)
            static_mac_map[key_pair] = entry;
        else
            dynamic_mac_map[key_pair] = entry;
    } catch (...) {
        return false;
    }
    return true;
}


inline bool nas_mac_table_info::get_mac_table_by_type(nas_mac_entry_map_t **mac_type_table, bool type_static)
{
    if(mac_type_table != NULL) {
        *mac_type_table = (type_static) ? &static_mac_map : &dynamic_mac_map;
        return true;
    }
    return false;

}


bool nas_mac_table_info::get_mac_entry_details (const nas_mac_entry_key &key_pair,
                                                nas_mac_entry_t *entry, bool type_static) {

    nas_mac_entry_map_t *mac_table = NULL;

    if (get_mac_table_by_type(&mac_table, type_static) == false) {
        return false;
    }

    auto it = mac_table->find(key_pair);
    if (it == mac_table->end()) {
        return false;
    }
    memcpy(entry, &it->second, sizeof(nas_mac_entry_t));

    return true;
}


bool nas_mac_table_info::delete_mac_entry (const nas_mac_entry_key &key_pair, bool type_static, bool flush_all) {

    nas_mac_entry_map_t *mac_table = NULL;

    if (get_mac_table_by_type(&mac_table, type_static) == false){
        return false;
    }

    if (flush_all) {
        mac_table->clear();
        return true;
    }

    auto it = mac_table->find(key_pair);

    if (it == mac_table->end()){
        return false;
    }

    mac_table->erase(it);
    return true;
}


bool nas_mac_table_info::is_mac_entry_present (const nas_mac_entry_key &key_pair, bool type_static) {

    nas_mac_entry_map_t *mac_table = NULL;

    if (get_mac_table_by_type(&mac_table, type_static) == false){
        return false;
    }

    auto it = mac_table->find(key_pair);

    if (it == mac_table->end()) {
        return false;
    }
    return true;
}


bool nas_mac_table_info::print_table (bool type_static) {

    nas_mac_entry_map_t     *mac_table = NULL;

    if (get_mac_table_by_type(&mac_table, type_static) == false) {
        return false;
    }

    char mac_string[MAC_STRING_LEN];
    for (auto it = mac_table->begin(); it != mac_table->end(); ++it) {
        /* first (pair: vlan_id, mac_addr) , second (entry) */

        NAS_MAC_LOG(INFO,"Key Vlan =%d Key MAC=%s Vlan_Id=%d",
                it->first.vlan_id,
                std_mac_to_string(&it->first.mac_addr, mac_string, MAC_STRING_LEN),
                it->second.entry_key.vlan_id);
    }
    return true;
}


static inline bool get_vlan_to_mac_address_map_by_type(nas_vlan_to_mac_addr_map_t **vlan_to_mac_addr_map, bool type_static)
{
    if(vlan_to_mac_addr_map != NULL) {
        *vlan_to_mac_addr_map = (type_static) ? &nas_vlan_to_mac_addr_map[0] : &nas_vlan_to_mac_addr_map[1];
        return true;
    }
    return false;
}


static inline bool get_mac_to_vlan_map_by_type(nas_mac_to_vlan_map_t **mac_to_vlan_map, bool type_static)
{
    if(mac_to_vlan_map != NULL) {
        *mac_to_vlan_map = (type_static) ? &nas_mac_to_vlan_map[0] : &nas_mac_to_vlan_map[1];
        return true;
    }
    return false;

}


static inline bool get_intf_to_mac_vlan_map_by_type(nas_intf_to_mac_vlan_map_t **intf_to_mac_vlan_map, bool type_static)
{
    if(intf_to_mac_vlan_map != NULL) {
        *intf_to_mac_vlan_map = (type_static) ? &nas_intf_to_mac_vlan_map[0] : &nas_intf_to_mac_vlan_map[1];
        return true;
    }
    return false;

}


static bool nas_mac_entry_action_supported(BASE_MAC_PACKET_ACTION_t action)
{
    return (action == BASE_MAC_PACKET_ACTION_FORWARD ||
            action == BASE_MAC_PACKET_ACTION_LOG ||
            action == BASE_MAC_PACKET_ACTION_TRAP ||
            action == BASE_MAC_PACKET_ACTION_DROP);
}


static t_std_error nas_mac_obj_to_entry (cps_api_object_t obj, nas_mac_entry_t *entry,
                                  bool *type_static, bool *type_set) {

    cps_api_object_it_t it;
    bool valid_param_set[4] = {false, false, false, false};
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    *type_set = false;
    *type_static = true;

    memset(entry, 0, sizeof(nas_mac_entry_t));
    entry->npu_configured = true;
    entry->os_configured =false;

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch ((int) cps_api_object_attr_id(it.attr)) {

            case BASE_MAC_TABLE_VLAN:
            case BASE_MAC_QUERY_VLAN:
                entry->entry_key.vlan_id = cps_api_object_attr_data_u16(it.attr);
                valid_param_set[1] = true;
                break;

            case BASE_MAC_TABLE_IFINDEX:
            case BASE_MAC_QUERY_IFINDEX:
                entry->ifindex = cps_api_object_attr_data_u32(it.attr);
                valid_param_set[2] = true;
                break;

            case BASE_MAC_TABLE_IFNAME:
            case BASE_MAC_QUERY_IFNAME:
            {
                const char * name = (const char *)cps_api_object_attr_data_bin(it.attr);
                interface_ctrl_t i;
                memset(&i,0,sizeof(i));
                strncpy(i.if_name,name,sizeof(i.if_name)-1);
                i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
                if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                    EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                            "Can't get interface control information for %s",name);
                        return STD_ERR(MAC,FAIL,0);
                }
                entry->ifindex = i.if_index;
                valid_param_set[2] = true;
                break;
            }
            case BASE_MAC_TABLE_MAC_ADDRESS:
            case BASE_MAC_QUERY_MAC_ADDRESS:
            {
                size_t mac_len = cps_api_object_attr_len(it.attr);
                if (mac_len < sizeof(hal_mac_addr_t)) {
                    NAS_MAC_LOG(ERR, "Invalid mac address format");
                    return STD_ERR(MAC,CFG,0);
                }
                memcpy(entry->entry_key.mac_addr, cps_api_object_attr_data_bin(it.attr),
                        sizeof(hal_mac_addr_t));
                valid_param_set[3] = true;
                break;
            }

            case BASE_MAC_TABLE_ACTIONS:
            {
                BASE_MAC_PACKET_ACTION_t pkt_action = (BASE_MAC_PACKET_ACTION_t)
                                                    cps_api_object_attr_data_u32(it.attr);
                if (!nas_mac_entry_action_supported(pkt_action)) {
                    NAS_MAC_LOG(ERR,  "Unsupported action type: %d", entry->pkt_action);
                    return STD_ERR(MAC,CFG,0);
                }
                else{
                    valid_param_set[0] = true;
                    entry->pkt_action = pkt_action;
                }
                break;
            }
            case BASE_MAC_QUERY_STATIC:
            case BASE_MAC_TABLE_STATIC:
                *type_static = cps_api_object_attr_data_u32(it.attr);
                *type_set = true;
                break;

            case BASE_MAC_TABLE_CONFIGURE_OS:
                entry->os_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            case BASE_MAC_TABLE_CONFIGURE_NPU:
                entry->npu_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            default:
                break;
        }
    }

    if( op == cps_api_oper_CREATE){
        /* validate the params if it is a create request. */
        if ((!valid_param_set[1]) ||
            (!valid_param_set[2]) || (!valid_param_set[3])) {
            NAS_MAC_LOG(ERR, " All the valid parameters(vlan/ifindex/mac)are not passed.");
            return STD_ERR(MAC,CFG,0);
        }
        if (!valid_param_set[0]) {
            /* Use FORWARD as default action if not specified */
            entry->pkt_action = BASE_MAC_PACKET_ACTION_FORWARD;
        }
    } else if (op == cps_api_oper_SET) {
        /* validate the params if it is a set request. */
        if (!valid_param_set[1] || !valid_param_set[3]) {
            NAS_MAC_LOG(ERR, " All the valid parameters(vlan/mac)are not passed.");
            return STD_ERR(MAC,CFG,0);
        }
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_cps_create_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;
    bool type_set, type_static;

    if ((rc = nas_mac_obj_to_entry(obj, &entry, &type_static, &type_set)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }

    return nas_mac_create_entry(&entry, type_static, false);
}


t_std_error nas_mac_cps_update_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;
    bool type_set, type_static;
    memset(&entry, 0, sizeof(nas_mac_entry_t));

    if ((rc = nas_mac_obj_to_entry(obj, &entry, &type_static, &type_set)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }
    return nas_mac_update_entry(&entry, type_static, false);
}


/* helper functions for delete */
/* *************************** */

static bool nas_mac_delete_entry_from_vlan_map(nas_vlan_to_mac_addr_map_t* vlan_to_mac_addr_map_ptr,
                                               nas_mac_entry_t *entry){
    /* vlan only option - iterate thru all the entries for that vlan*/

    auto it_vlan_to_addr_temp = vlan_to_mac_addr_map_ptr->find(entry->entry_key.vlan_id);

    if (it_vlan_to_addr_temp == vlan_to_mac_addr_map_ptr->end()) {
        NAS_MAC_LOG(DEBUG,  "No MAC entry with Vlan id %d exists", entry->entry_key.vlan_id);
        return false;
    }

    /* remove the mac entry from vlan_to_mac list */
    it_vlan_to_addr_temp->second.erase(entry->entry_key.mac_addr);

    if(it_vlan_to_addr_temp->second.empty()){
        vlan_to_mac_addr_map_ptr->erase(it_vlan_to_addr_temp);
    }

    return true;
}


static bool nas_mac_delete_entry_from_mac_map(nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr,
                                              nas_mac_entry_t *entry) {
    it_mac_to_vlan_t it_mac_to_vlan_temp = nas_get_it_mac_to_vlan(entry->entry_key.mac_addr,
                                                                  mac_to_vlan_map_ptr);
    if (it_mac_to_vlan_temp == mac_to_vlan_map_ptr->end()) {
        NAS_MAC_LOG(DEBUG,  " Error in finding MAC to vlan map ptr");
        return false;
    }

    it_mac_to_vlan_temp->second.erase(entry->entry_key.vlan_id);

    if(it_mac_to_vlan_temp->second.empty()){
        mac_to_vlan_map_ptr->erase(it_mac_to_vlan_temp);
    }

    return true;

}


static bool nas_mac_delete_entry_from_if_map(nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr,
                                             nas_mac_entry_t *entry) {

    auto it = intf_to_mac_vlan_map_ptr->begin();
    while (it != intf_to_mac_vlan_map_ptr->end()) {
        it->second.erase(entry->entry_key);
        if(it->second.empty()){
         it = intf_to_mac_vlan_map_ptr->erase(it);
         continue;
        }
        ++it;
    }
    return true;

}


static bool is_filter_type_present (nas_mac_entry_t *entry, del_filter_type_t filter_type) {
    hal_mac_addr_t zero_mac;
    memset(&zero_mac, 0, sizeof(hal_mac_addr_t));
    switch (filter_type) {
        case DEL_VLAN_FILTER:
            if (entry->entry_key.vlan_id != 0) {
                return true;
            }
            break;
        case DEL_MAC_FILTER:
            if (memcmp(entry->entry_key.mac_addr, zero_mac, sizeof(hal_mac_addr_t)) != 0) {
                return true;
            }
            break;
        case DEL_IF_FILTER:
            if (entry->ifindex != 0) {
                return true;
            }
            break;
        default :
            break;
    }
    return false;
}

static t_std_error nas_mac_update_entry_in_os(nas_mac_entry_t *entry,bool is_static,
                                              cps_api_operation_types_t op){
     static char buff[1000];
     cps_api_object_t obj = cps_api_object_init(buff,sizeof(buff));
     cps_api_object_set_type_operation(cps_api_object_key(obj),op);
     cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX,entry->ifindex);
     cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_STATIC,is_static);
     cps_api_object_attr_add_u16(obj,BASE_MAC_TABLE_VLAN,entry->entry_key.vlan_id);
     cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS,(void *)&entry->entry_key.mac_addr,
                                 sizeof(entry->entry_key.mac_addr));
     return nas_os_mac_update_entry(obj);
}


static t_std_error nas_mac_flush_all_entries (nas_mac_entry_t *entry, bool static_type) {
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;

    if (get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding VLAN to MAC Addr map");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding MAC to VLAN map");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding Interface to MAC-VLAN map");
        return STD_ERR(MAC,NEXIST,0);
    }
    vlan_to_mac_addr_map_ptr->clear();
    mac_to_vlan_map_ptr->clear();
    intf_to_mac_vlan_map_ptr->clear();
    nas_mac_table.delete_mac_entry(entry->entry_key, static_type, true);
    return STD_ERR_OK;
}


static t_std_error nas_mac_delete_vlan_filter(nas_mac_entry_t *entry, ndi_mac_delete_type_t *del_type,
                                     bool mac_filter_on, bool static_type) {
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;
    nas_mac_entry_t entry_temp;
    char mac_string[MAC_STRING_LEN];
    memset(&entry_temp, 0 , sizeof(nas_mac_entry_t));

    if (!(get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                "Error in finding VLAN to MAC Addr map for delete based on vlan filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                "Error in finding MAC to VLAN map for delete based on vlan filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                "Error in finding Interface to MAC-VLAN map for delete based on vlan filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    *del_type = NDI_MAC_DEL_BY_VLAN;
    nas_mac_struct nas_str_temp;

    it_vlan_to_addr_t it_vlan_to_addr_temp =
        vlan_to_mac_addr_map_ptr->find(entry->entry_key.vlan_id);
    if (it_vlan_to_addr_temp != vlan_to_mac_addr_map_ptr->end()) {
        entry_temp.entry_key.vlan_id = entry->entry_key.vlan_id;
        auto it = it_vlan_to_addr_temp->second.begin();
        while(it != it_vlan_to_addr_temp->second.end()) {
            nas_str_temp = *it;
            memcpy(&entry_temp.entry_key.mac_addr, &nas_str_temp.mac_addr, sizeof(hal_mac_addr_t)) ;
            /* remove from mac map */
            if (!(nas_mac_delete_entry_from_mac_map(mac_to_vlan_map_ptr, &entry_temp))) {
                 NAS_MAC_LOG(ERR,
                         "Error deleting entry from mac map vlan %d, mac %s",
                         entry_temp.entry_key.vlan_id,
                         std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                           mac_string, MAC_STRING_LEN));
                 return STD_ERR(MAC,FAIL,0);
            }
            /* remove from if map */
            if (!(nas_mac_delete_entry_from_if_map(intf_to_mac_vlan_map_ptr, &entry_temp))) {
                 NAS_MAC_LOG(ERR,
                         "Error deleting entry from if map vlan %d, mac %s",
                         entry_temp.entry_key.vlan_id,
                         std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                           mac_string, MAC_STRING_LEN));
                return STD_ERR(MAC,FAIL,0);
            }
            /* remove from vlan map  */
            auto it1 = it;
            ++it;
            it_vlan_to_addr_temp->second.erase(*it1);

            /* Updating global mac table */
            nas_mac_table.delete_mac_entry(entry_temp.entry_key, static_type, false);
            if(it_vlan_to_addr_temp->second.empty()){
                vlan_to_mac_addr_map_ptr->erase(it_vlan_to_addr_temp);
                break;
            }
        }
    }
    return STD_ERR_OK;
}

static t_std_error nas_mac_delete_mac_filter(nas_mac_entry_t *entry, ndi_mac_delete_type_t *del_type,
                                     bool static_type) {
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;
    nas_mac_entry_t entry_temp;
    char mac_string[MAC_STRING_LEN];
    memset(&entry_temp, 0 , sizeof(nas_mac_entry_t));

    if (!(get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
            "Error in finding VLAN to MAC Addr map for delete based on mac filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
            "Error in finding MAC to VLAN map for delete based on mac filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
            "Error in finding Interface to MAC-VLAN map for delete based on mac filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    *del_type = NDI_MAC_DEL_SINGLE_ENTRY;
    it_mac_to_vlan_t it = nas_get_it_mac_to_vlan(entry->entry_key.mac_addr, mac_to_vlan_map_ptr);
    if (it == mac_to_vlan_map_ptr->end()) {
        NAS_MAC_LOG(ERR,  " Error in finding MAC to vlan map ptr");
        return STD_ERR(MAC,NEXIST,0);
    }
    it_nas_vlan_list_t it_nas_vlan_list_temp;
    it_nas_vlan_list_t it_nas_vlan_list_temp_ptr;

    it_nas_vlan_list_temp = it->second.find(entry->entry_key.vlan_id);
    if(it_nas_vlan_list_temp == it->second.end()){
        EV_LOGGING(L2MAC,ERR,"MAC-DEL","Failed to find the mac to vlan entry");
        return STD_ERR(MAC,NEXIST,0);
    }
    memcpy(entry_temp.entry_key.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t)) ;
    entry_temp.entry_key.vlan_id = entry->entry_key.vlan_id;
    /* remove from vlan map */
    if (!(nas_mac_delete_entry_from_vlan_map(vlan_to_mac_addr_map_ptr, &entry_temp))) {
          NAS_MAC_LOG(ERR,
              "Error deleting entry from vlan map vlan %d, mac %s",
               entry_temp.entry_key.vlan_id,
               std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                 mac_string, MAC_STRING_LEN));
        return STD_ERR(MAC,FAIL,0);
    }
    /* remove from if map */
    if (!(nas_mac_delete_entry_from_if_map(intf_to_mac_vlan_map_ptr, &entry_temp))) {
          NAS_MAC_LOG(ERR,
                  "Error deleting entry from if map vlan %d, mac %s",
                   entry_temp.entry_key.vlan_id,
                   std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                     mac_string, MAC_STRING_LEN));
        return STD_ERR(MAC,FAIL,0);
    }
    /* remove from mac map */

    it_nas_vlan_list_temp_ptr = it_nas_vlan_list_temp;
    it_nas_vlan_list_temp++;
    it->second.erase(*it_nas_vlan_list_temp_ptr);

    nas_mac_entry_t old_entry;
    if(nas_mac_table.get_mac_entry_details(entry->entry_key, &old_entry, static_type) == false){
        NAS_MAC_LOG(ERR,"Get mac details failed for mac = %s, vlan = 0x%x ",
                    std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                    entry->entry_key.vlan_id);
        return STD_ERR(MAC,FAIL,0);
    }

    if(old_entry.os_configured == true){
        if(nas_mac_update_entry_in_os(&old_entry,false,cps_api_oper_DELETE)!=STD_ERR_OK){
            return STD_ERR(MAC,FAIL,0);
        }
    }

    /* Updating global mac table */
    nas_mac_table.delete_mac_entry(entry_temp.entry_key, static_type, false);

    if(it->second.empty()){
        mac_to_vlan_map_ptr->erase(it);
    }

    return STD_ERR_OK;
}

static t_std_error nas_mac_delete_if_filter(nas_mac_entry_t *entry, ndi_mac_delete_type_t *del_type,
                                     bool vlan_filter_on, bool mac_filter_on, bool static_type) {
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;
    nas_mac_entry_t entry_temp;
    char mac_string[MAC_STRING_LEN];
    memset(&entry_temp, 0 , sizeof(nas_mac_entry_t));

    if (!(get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                    "Error in finding VLAN to MAC Addr map for delete based on if filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                "Error in finding MAC to VLAN map for delete based on if filter");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (!(get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type))) {
        NAS_MAC_LOG(ERR,
                "Error in finding Interface to MAC-VLAN map for delete based on if filter");
        return STD_ERR(MAC,NEXIST,0);
    }
    *del_type = NDI_MAC_DEL_BY_PORT;
    if (vlan_filter_on) {
        *del_type = NDI_MAC_DEL_BY_PORT_VLAN;
    }
    it_intf_to_mac_vlan_t it_intf_to_mac_vlan_temp =
         intf_to_mac_vlan_map_ptr->find(entry->ifindex);

    if (it_intf_to_mac_vlan_temp != intf_to_mac_vlan_map_ptr->end()) {
        auto it = it_intf_to_mac_vlan_temp->second.begin();
        while (it != it_intf_to_mac_vlan_temp->second.end()) {


            if ((vlan_filter_on) &&
                (it->vlan_id != entry->entry_key.vlan_id)) {
                    ++it;
                continue;
            }
            entry_temp.entry_key.vlan_id = it->vlan_id;
            memcpy(entry_temp.entry_key.mac_addr, it->mac_addr, sizeof(hal_mac_addr_t)) ;
            /* remove from vlan map */
            if (!(nas_mac_delete_entry_from_vlan_map(vlan_to_mac_addr_map_ptr, &entry_temp))) {
                  NAS_MAC_LOG(ERR,
                              "Error deleting entry from vlan map vlan %d, mac %s",
                               entry_temp.entry_key.vlan_id,
                               std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                                 mac_string, MAC_STRING_LEN));
                return STD_ERR(MAC,FAIL,0);
            }
            /* remove from mac map */
            if (!(nas_mac_delete_entry_from_mac_map(mac_to_vlan_map_ptr, &entry_temp))) {
                  NAS_MAC_LOG(ERR,
                              "Error deleting entry from mac map vlan %d, mac %s",
                               entry_temp.entry_key.vlan_id,
                               std_mac_to_string(&entry_temp.entry_key.mac_addr,
                                                 mac_string, MAC_STRING_LEN));
                return STD_ERR(MAC,FAIL,0);
            }
            /* now remove it from if map */
            ++it;

            if (it_intf_to_mac_vlan_temp->second.empty()) {
                NAS_MAC_LOG(ERR, "Error deleting from if map , empty");
                return STD_ERR(MAC,FAIL,0);
            }
            it_intf_to_mac_vlan_temp->second.erase(entry_temp.entry_key);
            nas_mac_table.delete_mac_entry(entry_temp.entry_key, static_type, false);
            if(it_intf_to_mac_vlan_temp->second.empty()){
                intf_to_mac_vlan_map_ptr->erase(it_intf_to_mac_vlan_temp);
                break;
            }
        }
    }
    return STD_ERR_OK;
}


t_std_error nas_mac_delete_entry (nas_mac_entry_t *entry, bool static_type, bool type_set, bool event_type) {

    bool vlan_filter_on, mac_filter_on, if_filter_on, flush_all_entries = false;
    bool single_entry_delete = false;
    ndi_mac_delete_type_t del_type = NDI_MAC_DEL_ALL_ENTRIES;

    vlan_filter_on = is_filter_type_present(entry, DEL_VLAN_FILTER);
    mac_filter_on = is_filter_type_present(entry, DEL_MAC_FILTER);
    if_filter_on = is_filter_type_present(entry, DEL_IF_FILTER);
    flush_all_entries = ((!vlan_filter_on) && (!mac_filter_on) && (!if_filter_on));
    single_entry_delete  = ((vlan_filter_on) && (mac_filter_on));

    if (flush_all_entries) {
        if (STD_ERR_OK != nas_mac_flush_all_entries(entry, static_type)) {
            return STD_ERR(MAC, FAIL, 0);
        }
    } else {
        if(single_entry_delete){
            if(entry->npu_configured == false && entry->os_configured == true){
                if(nas_mac_update_entry_in_os(entry,false,cps_api_oper_DELETE)==STD_ERR_OK){
                    return STD_ERR_OK;
                }
            }
            if(STD_ERR_OK != nas_mac_delete_mac_filter(entry, &del_type, static_type)){
                return STD_ERR(MAC, FAIL, 0);
            }
        }
        else if (if_filter_on) {
            if(STD_ERR_OK != nas_mac_delete_if_filter(entry, &del_type,
                                                      vlan_filter_on, mac_filter_on, static_type)){
                return STD_ERR(MAC, FAIL, 0);
            }
            if (!single_entry_delete) {
                if ((!type_set)) {
                    if(STD_ERR_OK != nas_mac_delete_if_filter(entry, &del_type,
                                                          vlan_filter_on, mac_filter_on, !static_type)){
                        return STD_ERR(MAC, FAIL, 0);
                    }
                }
            }
        } else if (vlan_filter_on) {
            if(STD_ERR_OK != nas_mac_delete_vlan_filter(entry, &del_type, mac_filter_on, static_type)){
                return STD_ERR(MAC, FAIL, 0);
            }

        }
    }

    /* Publish only when learned from NPU */
    if(event_type){
        if(nas_mac_publish_entry(entry,static_type,false,cps_api_oper_DELETE) != STD_ERR_OK){
            NAS_MAC_LOG(INFO,"Failed to publish MAC delete event");
        }
    }

    /* Queue the request to the MAC hw operations queue */
    if(!event_type){
        nas_mac_request_entry_t req_entry;
        req_entry.op_type = NAS_MAC_DEL;
        memcpy(&(req_entry.entry) ,entry,sizeof(nas_mac_entry_t));
        req_entry.static_type = static_type;
        req_entry.del_type = del_type;
        req_entry.subtype_all = type_set;

        nas_mac_request_queue_t & req_queue = nas_mac_get_request_queue();
        req_queue.push(std::move(req_entry));
    }
    return STD_ERR_OK;
}

t_std_error nas_mac_cps_delete_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;
    cps_api_object_it_t it;
    bool type_set, type_static = false;

    cps_api_object_it_begin(obj, &it);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
          int id = (int)cps_api_object_attr_id(it.attr);
          NAS_MAC_LOG(INFO, " Got delete filter id 0x%x , %d" , id, id);
    }

    if ((rc = nas_mac_obj_to_entry(obj, &entry, &type_static, &type_set)) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Object to Entry conversion failed ");
        return rc;
    }
    std_mutex_simple_lock_guard lock(nas_mac_get_request_mutex());
    if((rc =nas_mac_delete_entry(&entry, type_static, type_set, false)) != STD_ERR_OK){
        return rc;
    }
    std_condition_var_signal(nas_mac_get_request_cv());

    return STD_ERR_OK;
}

t_std_error nas_mac_flush_vlan_entries_of_port(uint32_t vlan, hal_ifindex_t port_index) {

    nas_mac_entry_t entry;
    memset(&entry, 0, sizeof(nas_mac_entry_t));
    entry.ifindex = port_index;
    entry.entry_key.vlan_id = vlan;
    std_mutex_simple_lock_guard lock(nas_mac_get_request_mutex());
    t_std_error rc;
    if((rc =nas_mac_delete_entry(&entry, false, true, false)) != STD_ERR_OK){
        return rc;
    }
    std_condition_var_signal(nas_mac_get_request_cv());
    return STD_ERR_OK;
}

static t_std_error nas_mac_create_entry_hw(nas_mac_entry_t *entry,bool static_type){
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = entry->ifindex;
    t_std_error rc;

    if ((rc = dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        EV_LOGGING(L2MAC,ERR,"NAS-MAC", "Get interface info failed for ifindex %d.",entry->ifindex);
        return rc;
    }

    ndi_mac_entry_t ndi_mac_entry;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));

    ndi_obj_id_t obj_id;
    if (intf_ctrl.int_type == nas_int_type_LAG) {
        if (nas_mac_lag_obj_id_get(entry->ifindex, obj_id) == STD_ERR_OK) {
            ndi_mac_entry.ndi_lag_id = obj_id;
        }
    }

    ndi_mac_entry.vlan_id = entry->entry_key.vlan_id;
    ndi_mac_entry.npu_id = 0; /* TODO: Handle multiple NPU scenerio */
    ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
    ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
    memcpy(ndi_mac_entry.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));
    ndi_mac_entry.is_static = static_type;
    ndi_mac_entry.action = entry->pkt_action;

    if((rc = ndi_create_mac_entry(&ndi_mac_entry)) != STD_ERR_OK){
        NAS_MAC_LOG(ERR,  " NDI MAC Create failed");
        return rc;
    }

    return STD_ERR_OK;
}


static t_std_error nas_mac_update_local_cache(nas_mac_entry_t *entry,bool static_type){

    uint8_t temp_mac_addr[sizeof(hal_mac_addr_t)];
    nas_mac_struct mac_str;
    memcpy(temp_mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));
    memcpy(mac_str.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));

    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;

    if (get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding VLAN to MAC Addr map");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR, "Error in finding MAC to VLAN map");
        return STD_ERR(MAC,NEXIST,0);
    }

    if (get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding Interface to MAC-VLAN map");
        return STD_ERR(MAC,NEXIST,0);
    }

    /* Updating VLAN to MAC address map table */
    it_vlan_to_addr_t it_vlan_to_addr_temp = vlan_to_mac_addr_map_ptr->find(entry->entry_key.vlan_id);
    if (it_vlan_to_addr_temp != vlan_to_mac_addr_map_ptr->end()) {
            it_vlan_to_addr_temp->second.insert(mac_str);
    } else {
        nas_mac_address_list_t mac_address_list_temp;
        mac_address_list_temp.insert(mac_str);
        vlan_to_mac_addr_map_ptr->insert(std::pair<hal_vlan_id_t, nas_mac_address_list_t> (entry->entry_key.vlan_id, mac_address_list_temp));
    }

    /* Updating MAC address to VLAN map table */
    hal_mac_addr_t hal_mac_address;
    memcpy(hal_mac_address,  temp_mac_addr, sizeof(hal_mac_addr_t));
    it_mac_to_vlan_t it_mac_to_vlan_temp = nas_get_it_mac_to_vlan(hal_mac_address,
                                                                  mac_to_vlan_map_ptr);

    if (it_mac_to_vlan_temp != mac_to_vlan_map_ptr->end()) {
            it_mac_to_vlan_temp->second.insert(entry->entry_key.vlan_id);
    } else {
        nas_vlan_list_t vlan_list_temp;
        vlan_list_temp.insert(entry->entry_key.vlan_id);

        mac_to_vlan_map_ptr->insert(std::pair<nas_mac_struct,
                                    nas_vlan_list_t> (nas_mac_struct(hal_mac_address), vlan_list_temp));
    }

    /* Updating interface to MAC address/VLAN map table */
    it_intf_to_mac_vlan_t it_intf_to_mac_vlan_temp = intf_to_mac_vlan_map_ptr->find(entry->ifindex);
    if (it_intf_to_mac_vlan_temp != intf_to_mac_vlan_map_ptr->end()) {
            it_intf_to_mac_vlan_temp->second.insert(entry->entry_key);
    } else {
        nas_mac_vlan_list_t mac_vlan_list_temp;
        nas_mac_entry_key entry_key_temp;
        entry_key_temp.vlan_id = entry->entry_key.vlan_id;
        memcpy(entry_key_temp.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t)) ;
        mac_vlan_list_temp.insert(entry_key_temp);
        intf_to_mac_vlan_map_ptr->insert(std::pair<hal_ifindex_t, nas_mac_vlan_list_t> (entry->ifindex, mac_vlan_list_temp));
    }
    return STD_ERR_OK;
}

t_std_error nas_mac_create_entry(nas_mac_entry_t *entry, bool static_type, bool event_type){

    t_std_error rc;
    nas_mac_entry_t   old_entry;
    char mac_string[MAC_STRING_LEN];
    ndi_mac_delete_type_t del_type;

    if (entry == NULL) {
        NAS_MAC_LOG(ERR, " entry is passed as NULL ");
        return STD_ERR(MAC,PARAM,0);
    }

    if (nas_mac_table.is_mac_entry_present(entry->entry_key, static_type) == true) {
        if(nas_mac_table.get_mac_entry_details(entry->entry_key, &old_entry, static_type) == false) {
             NAS_MAC_LOG(ERR, "Get mac details failed for mac = %s, vlan = 0x%x ",
                     std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                     entry->entry_key.vlan_id);
             return STD_ERR(MAC,PARAM,0);
        }

        if(entry->os_configured==true){
            if((rc = nas_mac_update_entry_in_os(entry,static_type,cps_api_oper_CREATE)) != STD_ERR_OK){
                return rc;
            }
        }

        if (old_entry.ifindex == entry->ifindex) {
            NAS_MAC_LOG(INFO, "Entry with vlan=%d Mac=%s if_index = %d already exists .",
                   entry->entry_key.vlan_id,
                   std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                   old_entry.ifindex);
            return STD_ERR_OK;
        } else if (static_type) { // static entry with same vlan, mac but different port
            NAS_MAC_LOG(INFO,
                   "Static Entry with vlan=%d Mac=%s if_index = %d exists, cannot update .",
                   entry->entry_key.vlan_id,
                   std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                   old_entry.ifindex);
            return STD_ERR(MAC, FAIL, 0);
        } else {

            /* mac move case - delete the old entry and following code will
             * recreate it with new index */
             NAS_MAC_LOG(INFO,
                   "mac move detected with vlan=%d Mac=%s old_if_index = %d new_if_index = %d.",
                   entry->entry_key.vlan_id,
                   std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                   old_entry.ifindex, entry->ifindex);
            del_type = NDI_MAC_DEL_BY_PORT;
            if(STD_ERR_OK != nas_mac_delete_mac_filter(&old_entry, &del_type,static_type)){
                NAS_MAC_LOG(ERR,  " delete returned failure");
                return STD_ERR(MAC, FAIL, 0);
            }
        }
    }

    /* For new static entry configuration, check if the entry is already present in dynamic cache table.
       If so,remove existing entry */
    if (static_type) {
        if (nas_mac_table.is_mac_entry_present(entry->entry_key, !static_type) == true) {
            nas_mac_table.get_mac_entry_details(entry->entry_key, &old_entry, !static_type);
            if (STD_ERR_OK != nas_mac_delete_mac_filter(&old_entry, &del_type, !static_type)) {
                return STD_ERR(MAC, FAIL, 0);
            }
        }
    }

    if(entry->os_configured==true){
        if((rc = nas_mac_update_entry_in_os(entry,static_type,cps_api_oper_CREATE)) != STD_ERR_OK){
            return rc;
        }
    }

    /* In case of event NDI does not need to be called, layer beneath of this is already programmed */
    if (!event_type)
    {
       if((rc = nas_mac_create_entry_hw(entry,static_type)) != STD_ERR_OK){
           return rc;
       }
    }

    /* Updating global mac table */
    nas_mac_table.add_mac_entry(*entry, static_type);


    /* Publish only when learned from NPU */
    if(event_type){
        if(nas_mac_publish_entry(entry,static_type,false,cps_api_oper_CREATE) != STD_ERR_OK){
            NAS_MAC_LOG(INFO,"Failed to publish MAC create event");
        }
    }


    return nas_mac_update_local_cache(entry,static_type);
}

t_std_error nas_mac_update_entry(nas_mac_entry_t *entry, bool static_type, bool event_type){
    t_std_error rc;
    nas_mac_entry_t   old_entry;
    ndi_obj_id_t obj_id;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;
    char mac_string[MAC_STRING_LEN];
    bool port_attr_changed = false;
    bool action_attr_changed = false;

    if (entry == NULL) {
        NAS_MAC_LOG(ERR, " entry is passed as NULL ");
        return STD_ERR(MAC,PARAM,0);
    }

    if (nas_mac_table.is_mac_entry_present(entry->entry_key, static_type) == true) {
        nas_mac_table.get_mac_entry_details(entry->entry_key, &old_entry, static_type);
        if ((entry->ifindex == 0 || old_entry.ifindex == entry->ifindex) &&
                (entry->pkt_action == 0 || old_entry.pkt_action == entry->pkt_action) &&
                (entry->os_configured == old_entry.os_configured)) {
            NAS_MAC_LOG(INFO,
                   "Entry with vlan=%d Mac=%s if_index = %d , Pkt Action = 0x%x already exists .",
                   entry->entry_key.vlan_id,
                   std_mac_to_string(&entry->entry_key.mac_addr, mac_string, MAC_STRING_LEN),
                   old_entry.ifindex, entry->pkt_action);
            return STD_ERR_OK;
        } else {
            /* modify case - update the global table, this will take care of updating
             * the new pkt action also if any */
            if (entry->ifindex == 0) {
                entry->ifindex = old_entry.ifindex;
            }
            if (entry->pkt_action == 0) {
                entry->pkt_action = old_entry.pkt_action;
            }
            nas_mac_table.add_mac_entry(*entry, static_type);

            if (old_entry.pkt_action != entry->pkt_action) {
                action_attr_changed = true;
            }

            if(old_entry.os_configured != entry->os_configured){
                cps_api_operation_types_t op = cps_api_oper_CREATE;
                if(old_entry.os_configured==true){
                    op = cps_api_oper_DELETE;
                }
                if((rc = nas_mac_update_entry_in_os(entry,static_type,op))!=
                        STD_ERR_OK){
                    return rc;
                }
            }

            /* update the local cache if if_index is being changed */
            if (old_entry.ifindex != entry->ifindex) {
                if(entry->os_configured){
                    if((rc = nas_mac_update_entry_in_os(entry,static_type,cps_api_oper_SET))!=
                                            STD_ERR_OK){
                        return rc;
                    }
                }
                port_attr_changed = true;
                /* update the interface-to-mac-vlan map */
                if (get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr,
                                                     static_type) == false) {
                    NAS_MAC_LOG(ERR,  "Error in finding Interface to MAC-VLAN map");
                    return STD_ERR(MAC,NEXIST,0);
                }

                /* if if_index is modified then delete from old if-vlan-mac entry
                 * and add to new */

                /* delete from old */
                it_intf_to_mac_vlan_t it_intf_to_mac_vlan_old =
                    intf_to_mac_vlan_map_ptr->find(old_entry.ifindex);

                if (it_intf_to_mac_vlan_old != intf_to_mac_vlan_map_ptr->end()) {
                    NAS_MAC_LOG(DEBUG,  "Deleting for old index map 0x%x",
                            old_entry.ifindex);
                    nas_mac_entry_t entry_temp;
                    memset(&entry_temp, 0 , sizeof(nas_mac_entry_t));
                    entry_temp.entry_key.vlan_id = entry->entry_key.vlan_id;
                    memcpy(entry_temp.entry_key.mac_addr, entry->entry_key.mac_addr,
                           sizeof(hal_mac_addr_t)) ;
                    it_intf_to_mac_vlan_old->second.erase(entry_temp.entry_key);
                    if (it_intf_to_mac_vlan_old->second.begin() ==
                            it_intf_to_mac_vlan_old->second.end()) {
                        intf_to_mac_vlan_map_ptr->erase(it_intf_to_mac_vlan_old);
                    }
                }
                /* add to the new */

                NAS_MAC_LOG(DEBUG,  "Adding to new index map 0x%x",
                            entry->ifindex);
                it_intf_to_mac_vlan_t it_intf_to_mac_vlan_temp =
                    intf_to_mac_vlan_map_ptr->find(entry->ifindex);
                if (it_intf_to_mac_vlan_temp != intf_to_mac_vlan_map_ptr->end()) {
                    it_intf_to_mac_vlan_temp->second.insert(entry->entry_key);
                } else {
                   nas_mac_vlan_list_t mac_vlan_list_temp;
                   nas_mac_entry_key entry_key_temp;
                   entry_key_temp.vlan_id = entry->entry_key.vlan_id;
                   memcpy(entry_key_temp.mac_addr, entry->entry_key.mac_addr,
                          sizeof(hal_mac_addr_t)) ;
                   mac_vlan_list_temp.insert(entry_key_temp);
                   intf_to_mac_vlan_map_ptr->insert(std::pair<hal_ifindex_t,
                           nas_mac_vlan_list_t> (entry->ifindex, mac_vlan_list_temp));
                }
            }
            /* update the hardware  entry*/
            interface_ctrl_t intf_ctrl;
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.if_index = entry->ifindex;

            if ((rc = dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                EV_LOGGING(L2MAC,ERR, "NAS-MAC", "Get interface info failed for %d.",entry->ifindex);
                return rc;
            }

            ndi_mac_entry_t ndi_mac_entry;
            memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));
            if (intf_ctrl.int_type == nas_int_type_LAG) {
                if (nas_mac_lag_obj_id_get(entry->ifindex, obj_id) == STD_ERR_OK) {
                    ndi_mac_entry.ndi_lag_id = obj_id;
                }
            }

            ndi_mac_entry.vlan_id = entry->entry_key.vlan_id;
            ndi_mac_entry.npu_id = 0; /* TODO: Handle multiple NPU scenerio */
            ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
            ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
            memcpy(ndi_mac_entry.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));
            ndi_mac_entry.is_static = static_type;
            ndi_mac_entry.action = entry->pkt_action;

            if (port_attr_changed) {

                if((rc = ndi_update_mac_entry(&ndi_mac_entry,
                                              NDI_MAC_ENTRY_ATTR_PORT_ID)) != STD_ERR_OK){
                    return rc;
                }
            }
            if (action_attr_changed) {
                if((rc = ndi_update_mac_entry(&ndi_mac_entry,
                                              NDI_MAC_ENTRY_ATTR_PKT_ACTION)) != STD_ERR_OK){
                    return rc;
                    /* TODO : if both port and action attributes changed and one update went thru
                     * succesfully but the later request failed, we need to revert the previous
                     * update as well before returning failure. This is a corner case race condition
                     * and don't expect to hit though.
                     */
                }
            }
        }
    } else {
        NAS_MAC_LOG(ERR,
                " NDI MAC update failed, didn't find a previous entry with same mac and vlan");
        return STD_ERR(MAC, NEXIST, 0);
    }
    return STD_ERR_OK;
}

static void nas_mac_fill_count_to_object(cps_api_object_t obj, uint32_t mac_count){

    cps_api_key_t key;

    cps_api_key_init(&key,cps_api_qualifier_TARGET,
                     (cps_api_object_category_types_t)cps_api_obj_CAT_BASE_MAC,
                     BASE_MAC_QUERY_OBJ,
                     0);

    cps_api_object_set_key(obj,&key);


    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_COUNT, mac_count);

}

static void nas_mac_fill_info_to_object(cps_api_object_t obj, nas_mac_entry_t *entry,
                                        bool static_type){

    cps_api_key_t key;

    cps_api_key_init(&key,cps_api_qualifier_TARGET,
                     (cps_api_object_category_types_t)cps_api_obj_CAT_BASE_MAC,
                     BASE_MAC_QUERY_OBJ,
                     0);

    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_VLAN, entry->entry_key.vlan_id);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_IFINDEX, entry->ifindex);
    cps_api_object_attr_add(obj,BASE_MAC_QUERY_MAC_ADDRESS, entry->entry_key.mac_addr,
                            sizeof(hal_mac_addr_t));
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_ACTIONS, entry->pkt_action);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_STATIC, static_type);
}

t_std_error nas_mac_get_all_info(cps_api_object_list_t list, bool static_type){

    nas_mac_entry_key key_pair;
    nas_mac_entry_t   _entry;
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr;
    nas_mac_struct mac_str;


    if (get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding VLAN to MAC Addr map");
        return STD_ERR(MAC,NEXIST,0);
    }

    for(auto it = vlan_to_mac_addr_map_ptr->begin() ; it != vlan_to_mac_addr_map_ptr->end() ; ++it){

        it_nas_mac_address_list_t it_nas_mac_address_list_temp;

        for ( it_nas_mac_address_list_temp = it->second.begin();
                it_nas_mac_address_list_temp != it->second.end(); ++it_nas_mac_address_list_temp) {

            key_pair.vlan_id = it->first;

            mac_str = *it_nas_mac_address_list_temp;
            memcpy(key_pair.mac_addr, mac_str.mac_addr, sizeof(hal_mac_addr_t));

            nas_mac_table.get_mac_entry_details(key_pair, &_entry, static_type);
            cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
            if (!obj) {
                return STD_ERR(MAC, NOMEM, 0);
            }

            nas_mac_fill_info_to_object(obj, &_entry, static_type);
        }
    }

    return STD_ERR_OK;
}

t_std_error nas_mac_get_count_info(uint16_t vlan_id, hal_ifindex_t if_index, bool static_type, uint32_t *count){

    uint32_t mac_count;
    if ((vlan_id == 0) && (if_index == 0)) {
        /* get global count , no filters */
        if (static_type) {
            mac_count = (uint32_t)nas_mac_table.static_entry_count();
        } else {
            mac_count = (uint32_t)nas_mac_table.dynamic_entry_count();
        }
    } else {
        mac_count = 0;
        nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr;
        if (get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type) == false) {
            NAS_MAC_LOG(ERR,  "Error in finding Interface to MAC-VLAN map");
            return STD_ERR(MAC, NEXIST, 0);
        }
        if (vlan_id == 0 ) {
             it_intf_to_mac_vlan_t it = intf_to_mac_vlan_map_ptr->find(if_index);
             if (it != intf_to_mac_vlan_map_ptr->end()) {
                mac_count = std::distance(it->second.begin(), it->second.end());
             }
        } else if (if_index == 0){
             nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr;
             if (get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr,
                                                     static_type) == false) {
                 NAS_MAC_LOG(ERR,  "Error in finding VLAN to MAC Addr map");
                 return STD_ERR(MAC, NEXIST, 0);
             }
             it_vlan_to_addr_t it = vlan_to_mac_addr_map_ptr->find(vlan_id);
             if (it != vlan_to_mac_addr_map_ptr->end()) {
                mac_count = std::distance(it->second.begin(), it->second.end());
             }
        } else {
             /* both vlan and interface filter, loop through and count. */
            it_intf_to_mac_vlan_t it = intf_to_mac_vlan_map_ptr->find(if_index);
            if (it != intf_to_mac_vlan_map_ptr->end()) {
                it_nas_mac_vlan_list_t it_nas_mac_vlan_list_temp;
                for ( it_nas_mac_vlan_list_temp = it->second.begin();
                it_nas_mac_vlan_list_temp != it->second.end(); ++it_nas_mac_vlan_list_temp) {
                    if (vlan_id == it_nas_mac_vlan_list_temp->vlan_id) {
                        mac_count++;
                    }
                }
            }
        }
    }

    *count = mac_count;

    return STD_ERR_OK;

}


t_std_error nas_mac_get_consolidated_count(cps_api_object_list_t list, uint16_t vlan_id,
                                           hal_ifindex_t if_index, bool static_type, bool static_type_set){

    uint32_t count = 0, count_other_type = 0;

    if (nas_mac_get_count_info(vlan_id, if_index, static_type, &count) == STD_ERR_OK) {
        if (!static_type_set && nas_mac_get_count_info(vlan_id, if_index, !static_type, &count_other_type) != STD_ERR_OK) {
            NAS_MAC_LOG(ERR,  " Error in getting count info");
            return STD_ERR(MAC,FAIL,0);
        }
        count += count_other_type;
    }  else {
        NAS_MAC_LOG(ERR,  " Error in getting count info");
        return STD_ERR(MAC,FAIL,0);
    }

    cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
    if (!obj) {
        return STD_ERR(MAC, NOMEM, 0);
    }

    nas_mac_fill_count_to_object(obj, count);

    return STD_ERR_OK;
}

t_std_error nas_mac_get_all_if_info(cps_api_object_list_t list, hal_ifindex_t if_index, bool static_type){
    nas_mac_entry_key key_pair;
    nas_mac_entry_t   _entry;
    nas_intf_to_mac_vlan_map_t *intf_to_mac_vlan_map_ptr = NULL;
    if (get_intf_to_mac_vlan_map_by_type(&intf_to_mac_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  " Error in finding VLAN to MAC Addr map");
        return STD_ERR(MAC,NEXIST,0);
    }
    /* find the entry from interface-to-vlan-mac map */
    it_intf_to_mac_vlan_t it = intf_to_mac_vlan_map_ptr->find(if_index);
    if (it == intf_to_mac_vlan_map_ptr->end()) {
        /* no entry found, just return */
        return STD_ERR_OK;
    }
    it_nas_mac_vlan_list_t it_nas_mac_vlan_list_temp;
    for ( it_nas_mac_vlan_list_temp = it->second.begin();
            it_nas_mac_vlan_list_temp != it->second.end(); ++it_nas_mac_vlan_list_temp) {
        key_pair.vlan_id = it_nas_mac_vlan_list_temp->vlan_id;
        memcpy(key_pair.mac_addr, it_nas_mac_vlan_list_temp->mac_addr, sizeof(hal_mac_addr_t));
        nas_mac_table.get_mac_entry_details(key_pair, &_entry, static_type);
        cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
        if (!obj) {
            return STD_ERR(MAC, NOMEM, 0);
        }
        nas_mac_fill_info_to_object(obj, &_entry, static_type);
    }
    return STD_ERR_OK;
}

t_std_error nas_mac_get_all_vlan_info(cps_api_object_list_t list, uint16_t vlan_id, bool static_type){

    nas_mac_entry_key key_pair;
    nas_mac_entry_t   _entry;
    nas_vlan_to_mac_addr_map_t *vlan_to_mac_addr_map_ptr = NULL;
    nas_mac_struct mac_str;

    if (get_vlan_to_mac_address_map_by_type(&vlan_to_mac_addr_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding VLAN to MAC Addr map");
        return STD_ERR(MAC,NEXIST,0);
    }

    /* find the entry from vlan to mac map */
    it_vlan_to_addr_t it = vlan_to_mac_addr_map_ptr->find(vlan_id);
    if (it == vlan_to_mac_addr_map_ptr->end()) {
        /* no entry found, just return */
        return STD_ERR_OK;
    }

    it_nas_mac_address_list_t it_nas_mac_address_list_temp;

    for ( it_nas_mac_address_list_temp = it->second.begin();
                it_nas_mac_address_list_temp != it->second.end(); ++it_nas_mac_address_list_temp) {

        key_pair.vlan_id = it->first;
        mac_str = *it_nas_mac_address_list_temp;
        memcpy(key_pair.mac_addr, &mac_str.mac_addr, sizeof(hal_mac_addr_t));

        nas_mac_table.get_mac_entry_details(key_pair, &_entry, static_type);
        cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
        if (!obj) {
            return STD_ERR(MAC, NOMEM, 0);
        }
        nas_mac_fill_info_to_object(obj, &_entry, static_type);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_get_all_mac_info(cps_api_object_list_t list, hal_mac_addr_t mac_addr, bool static_type){
    nas_mac_entry_key key_pair;
    nas_mac_entry_t   _entry;
    nas_mac_to_vlan_map_t *mac_to_vlan_map_ptr = NULL;

    if (get_mac_to_vlan_map_by_type(&mac_to_vlan_map_ptr, static_type) == false) {
        NAS_MAC_LOG(ERR,  "Error in finding MAC to VLAN map");
        return STD_ERR(MAC,NEXIST,0);
    }
    /* find the entry from mac to vlan map */
    it_mac_to_vlan_t it = nas_get_it_mac_to_vlan(mac_addr, mac_to_vlan_map_ptr);
    if (it == mac_to_vlan_map_ptr->end()) {
        /* no entry found, just return */
        return STD_ERR_OK;
    }
    it_nas_vlan_list_t it_nas_vlan_list_temp;

    for (it_nas_vlan_list_temp = it->second.begin();
            it_nas_vlan_list_temp != it->second.end(); ++it_nas_vlan_list_temp) {


        key_pair.vlan_id = *it_nas_vlan_list_temp;
        memcpy(key_pair.mac_addr, mac_addr, sizeof(hal_mac_addr_t));
        nas_mac_table.get_mac_entry_details(key_pair, &_entry, static_type);
        cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
        if (!obj) {
            return STD_ERR(MAC, NOMEM, 0);
        }

        nas_mac_fill_info_to_object(obj, &_entry, static_type);
    }

    return STD_ERR_OK;
}


static bool nas_mac_flush_entries(cps_api_object_t obj,const cps_api_object_it_t & it){

    cps_api_object_it_t it_lvl_1 = it;
    cps_api_attr_id_t ids[3] = {BASE_MAC_FLUSH_INPUT_FILTER,0, BASE_MAC_FLUSH_INPUT_FILTER_VLAN };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    bool type_set = true;
    nas_mac_entry_t entry;

    std_mutex_simple_lock_guard lock(nas_mac_get_request_mutex());
    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        memset(&entry,0,sizeof(nas_mac_entry_t));
        ids[1] = cps_api_object_attr_id (it_lvl_1.attr);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_VLAN;
        cps_api_object_attr_t vlan_attr = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFINDEX;
        cps_api_object_attr_t ifindex_attr = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFNAME;
        cps_api_object_attr_t ifname_attr = cps_api_object_e_get(obj,ids,ids_len);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_ALL;
        cps_api_object_attr_t filter_all_attr = cps_api_object_e_get(obj,ids,ids_len);
        if(vlan_attr == NULL && ifindex_attr == NULL){
            continue;
        }

        if(filter_all_attr){
             type_set = (bool)cps_api_object_attr_data_u32(filter_all_attr);
        }

        if(vlan_attr){
             entry.entry_key.vlan_id = cps_api_object_attr_data_u16(vlan_attr);
        }

        if(ifindex_attr){
             entry.ifindex = cps_api_object_attr_data_u32(ifindex_attr);
        }

        if(ifname_attr){
             const char * name = (const char *)cps_api_object_attr_data_bin(ifname_attr);
             interface_ctrl_t i;
             memset(&i,0,sizeof(interface_ctrl_t));
             strncpy(i.if_name,name,sizeof(i.if_name)-1);
             i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
             if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                 EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                     "Can't get interface control information for %s",name);
                      return false;
             }
             entry.ifindex = i.if_index;
        }

        if( nas_mac_delete_entry (&entry,false, type_set,false) != STD_ERR_OK){
            std_condition_var_signal(nas_mac_get_request_cv());
            return false;
        }
    }
    std_condition_var_signal(nas_mac_get_request_cv());
    return true;
}


t_std_error nas_mac_cps_flush_entry(cps_api_object_t obj){

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {

        case BASE_MAC_FLUSH_INPUT_FILTER:
            if(!nas_mac_flush_entries(obj,it)){
                return STD_ERR(MAC,FAIL,0);
            }
            break;

        default:
            break;
        }
    }

    return STD_ERR_OK;
}

t_std_error nas_mac_handle_if_down(hal_ifindex_t ifindex){
    t_std_error rc;
    nas_mac_entry_t entry;
    memset(&entry,0,sizeof(nas_mac_entry_t));
    entry.ifindex = ifindex;
    std_mutex_simple_lock_guard lock(nas_mac_get_request_mutex());
    if( (rc =nas_mac_delete_entry (&entry,false,true,false)) != STD_ERR_OK){
        return rc;
    }
    std_condition_var_signal(nas_mac_get_request_cv());
    return STD_ERR_OK;
}
