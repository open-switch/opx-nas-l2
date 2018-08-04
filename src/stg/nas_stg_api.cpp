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
 * filename: nas_stg_api.cpp
 */

#include "nas_stg_api.h"
#include "dell-interface.h"
#include "std_error_codes.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "hal_if_mapping.h"
#include "nas_ndi_stg.h"
#include "nas_base_utils.h"
#include "std_mutex_lock.h"
#include "nas_linux_l2.h"
#include "dell-base-stg.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_if_utils.h"

#include <string>
#include <stdlib.h>
#include <map>

/*@TODO update this value and get it from SAI when SAI STG is available */
#define MAX_STG_ID 512

// Default switch id to be used for handling os requests */
static const int default_switch_id = 0;

// NAS STG Id map
static nas::id_generator_t nas_stg_ids(MAX_STG_ID);

// Mutex for NAS STG APIs
static std_mutex_lock_create_static_init_fast(nas_stg_mutex);

// Table to maintain STG Entries
static auto nas_stg_table = new nas_stg_table_t;

// Bridge to STG Id map
static auto bridge_to_stg_map = new nas_br_to_stg_map_t;

// Bridge to VLAN Id map
static auto bridge_to_vlan_map = *new nas_br_to_vlan_map_t;

// VLAN to STG Map
static auto vlan_to_stg_map = *new nas_vlan_to_stg_map_t;

// Switch to NPU Ids map
static auto switch_to_npu_map = new nas_stg_switch_npu_map_t;

// Switch Id to default STG Id map
static auto switch_to_default_stg_map = new nas_stg_switch_defult_stg_map_t;

// Map which maintains lag and its member ports
static auto nas_lag_map = new nas_stg_lag_map_t;

BASE_STG_INTERFACE_STATE_t default_stg_state = BASE_STG_INTERFACE_STATE_FORWARDING;

typedef enum{
    OS_STATE_DISABLED=0,
    OS_STATE_LISTENING,
    OS_STATE_LEARNING,
    OS_STATE_FORWARDING,
    OS_STATE_BLOCKING,
}os_stp_state_t;

static auto
to_os_stp_state = new std::unordered_map<BASE_STG_INTERFACE_STATE_t,os_stp_state_t,std::hash<int>>{
    { BASE_STG_INTERFACE_STATE_DISABLED,OS_STATE_DISABLED } ,
    { BASE_STG_INTERFACE_STATE_LISTENING,OS_STATE_LISTENING },
    { BASE_STG_INTERFACE_STATE_LEARNING,OS_STATE_LEARNING } ,
    { BASE_STG_INTERFACE_STATE_FORWARDING,OS_STATE_FORWARDING } ,
    { BASE_STG_INTERFACE_STATE_BLOCKING,OS_STATE_BLOCKING }
};

static auto
from_os_stp_state = new std::unordered_map<os_stp_state_t,BASE_STG_INTERFACE_STATE_t,std::hash<int>>{
    { OS_STATE_DISABLED,BASE_STG_INTERFACE_STATE_DISABLED },
    { OS_STATE_LISTENING,BASE_STG_INTERFACE_STATE_LISTENING },
    { OS_STATE_LEARNING,BASE_STG_INTERFACE_STATE_LEARNING },
    { OS_STATE_FORWARDING,BASE_STG_INTERFACE_STATE_FORWARDING },
    { OS_STATE_BLOCKING,BASE_STG_INTERFACE_STATE_BLOCKING }
};


static inline unsigned int nas_stg_get_next_index() {
    return nas_stg_ids.alloc_id();
}


static inline void nas_stg_remove_index(unsigned int ix) {
    nas_stg_ids.release_id(ix);
}


static bool nas_stg_intf_to_port(hal_ifindex_t ifindex, interface_ctrl_t *intf_ctrl) {
    memset(intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl->q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl->if_index = ifindex;

    if (dn_hal_get_interface_info(intf_ctrl) != STD_ERR_OK) {
        NAS_STG_LOG(ERR,  "Interface %d has NO slot %d, port %d", intf_ctrl->if_index,
        intf_ctrl->npu_id, intf_ctrl->port_id);
        return false;
    }

    return true;
}


static bool nas_update_lag_stp_state(nas_stg_entry_t * entry, interface_ctrl_t & lag_intf,
                                     BASE_STG_INTERFACE_STATE_t state){

    if(lag_intf.int_type != nas_int_type_LAG){
        NAS_STG_LOG(ERR,"Interface type %d not supported to updated STG instance", lag_intf.int_type);
        return false;
    }

    ndi_obj_id_t lag_id;
    if(nas_get_lag_id_from_if_index(lag_intf.if_index,&lag_id) != STD_ERR_OK){
        return false;
    }


    if (ndi_stg_set_stp_lag_state(lag_intf.npu_id,
        entry->npu_to_stg_map.find(lag_intf.npu_id)->second, lag_id,state)
        != STD_ERR_OK) {
        return false;
    }

    entry->stp_states[lag_intf.if_index]=state;
    NAS_STG_LOG(DEBUG,  "Updated the STP state to %d for interface index %d in " "STG Id %d",
                state, lag_intf.if_index, entry->nas_stg_id);

    return true;

}


static bool nas_update_stp_state(nas_stg_entry_t * entry, hal_ifindex_t ifindex,
                                                BASE_STG_INTERFACE_STATE_t state) {
    interface_ctrl_t intf_ctrl;
    BASE_STG_INTERFACE_STATE_t stp_state;

    /*
     * Check if index is a LAG if it is then use the lag members to updates its stp state
     * otherwise use the normal physical interface index
     */

    if (!nas_stg_intf_to_port(ifindex, &intf_ctrl)) {
        return false;
    }

    if(intf_ctrl.int_type == nas_int_type_LAG){
       return nas_update_lag_stp_state(entry,intf_ctrl,state);
    } else if( intf_ctrl.int_type == nas_int_type_PORT || intf_ctrl.int_type == nas_int_type_FC){

        //Receive the STP Port State from NPU
        if (ndi_stg_get_stp_port_state(intf_ctrl.npu_id,
                entry->npu_to_stg_map.find(intf_ctrl.npu_id)->second, intf_ctrl.port_id, &stp_state)
                != STD_ERR_OK) {
            return false;
        }

        NAS_STG_LOG(DEBUG, "New STP State %d, Existing STP State %d", state, stp_state);

        /*
         * Check the new STP State and existing state if they are the same, and new
         * state is disabled then don't update
         */

        if ((stp_state == BASE_STG_INTERFACE_STATE_BLOCKING)
                && (state == BASE_STG_INTERFACE_STATE_DISABLED)) {
            NAS_STG_LOG(DEBUG,  "Already Updated STP state to %d for interface %d",
                        state, ifindex);
            return true;
        }


        if (ndi_stg_set_stp_port_state(intf_ctrl.npu_id,
                entry->npu_to_stg_map.find(intf_ctrl.npu_id)->second, intf_ctrl.port_id,state)
                != STD_ERR_OK) {
            return false;
        }
        entry->stp_states[ifindex]=state;
        NAS_STG_LOG(DEBUG,  "Updated the STP state to %d for interface index %d in " "STG Id %d",
            state, ifindex, entry->nas_stg_id);
    }else{
        NAS_STG_LOG(ERR,"Updating STG state for intf type %d not supported",intf_ctrl.int_type);
    }
    return true;
}


bool nas_create_stg_for_vlan(hal_vlan_id_t id,hal_ifindex_t bid){


    nas_stg_entry_t entry;
    ndi_stg_id_t ndi_stg_id;


    //For Open Source default switch will be always 0
    entry.switch_id = default_switch_id;

    auto npu_it = switch_to_npu_map->find(entry.switch_id);
    if (npu_it == switch_to_npu_map->end()) {
        NAS_STG_LOG(ERR,  "No such switch ID %d exist", entry.switch_id);
        return false;
    }

    nas_stg_npu_ids & npu_ids = npu_it->second;

    // Create a new instance in all the NPU
    for (auto it = npu_ids.begin(); it != npu_ids.end(); ++it) {
        if (ndi_stg_add(*it, &ndi_stg_id) != STD_ERR_OK) {
            return false;
        }

        if (ndi_stg_update_vlan(*it, ndi_stg_id, id) != STD_ERR_OK) {
            return false;
        }

        entry.npu_to_stg_map.insert(npu_to_stg_map_pair(*it, ndi_stg_id));
    }

    entry.nas_stg_id = nas_stg_get_next_index();
    bridge_to_stg_map->insert({bid,entry.nas_stg_id});
    entry.vlan_list.insert(id);
    entry.bridge_index = bid;
    entry.cps_created = false;
    vlan_to_stg_map[id] = entry.nas_stg_id;
    nas_stg_table->insert(nas_stg_table_pair(entry.nas_stg_id, std::move(entry)));
    NAS_STG_LOG(DEBUG, "New STG Entry with id %d created", entry.nas_stg_id);
    return true;
}

static bool nas_stg_create_for_bridge(hal_ifindex_t bid) {

    // Check if Bridge has a vlan else return
    auto vit = bridge_to_vlan_map.find(bid);

    if (vit != bridge_to_vlan_map.end()) {

        // If VLAN ID has an associated STG instance don't create new instance
        auto sit = vlan_to_stg_map.find(vit->second);
        if(sit != vlan_to_stg_map.end()){
            auto entry_it = nas_stg_table->find(sit->second);
            if (entry_it != nas_stg_table->end()){
                nas_stg_entry_t * entry = &(entry_it->second);
                if(entry->vlan_list.size()>1){
                    NAS_STG_LOG(DEBUG,"Create new STG instance for vlan %d",sit->first);
                    if(!nas_create_stg_for_vlan(vit->second,bid)){
                        return false;
                    }
                    entry->vlan_list.erase(vit->second);
                }
            }
        }
        // If VLAN ID does not have a STG instance associated create new instance
        if (sit == vlan_to_stg_map.end()) {
            if(!nas_create_stg_for_vlan(vit->second,bid)){
                return false;
            }
        }
    }
    return true;
}

static bool nas_stg_update_os_stp_state(hal_ifindex_t intfindex,
                BASE_STG_INTERFACE_STATE_t state, hal_vlan_id_t vlan_id, bool default_entry) {

    /*
     * Don't need to program listening and learning in the Linux
     * kernel
     */
    if(state != BASE_STG_INTERFACE_STATE_FORWARDING &&
        state != BASE_STG_INTERFACE_STATE_DISABLED &&
        state != BASE_STG_INTERFACE_STATE_BLOCKING){
        return true;
    }

    cps_api_object_guard og(cps_api_object_create());

    if (og.get()==nullptr) {
        NAS_STG_LOG(ERR,"Failed to create a new object");
        return false;
    }

    cps_api_object_attr_add_u32(og.get(), BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX, intfindex);

    /* If state is blocking then pass the disabled state to kernel as kernel
       puts the state in forwarding after putting the state in blocking */
    if (state == BASE_STG_INTERFACE_STATE_BLOCKING){
        state = BASE_STG_INTERFACE_STATE_DISABLED;
    }


    auto it = to_os_stp_state->find(state);
    if(it == to_os_stp_state->end()){
        NAS_STG_LOG(ERR,"Invalid STP State %d to update os",state);
        return false;
    }
    cps_api_object_attr_add_u32(og.get(), BASE_STG_ENTRY_INTF_STATE, it->second);

    cps_api_object_attr_add_u32(og.get(), BASE_STG_ENTRY_VLAN, vlan_id);

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = intfindex;

    if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
        cps_api_object_attr_add(og.get(), BASE_STG_ENTRY_INTF_IF_NAME, (const void *)intf_ctrl.if_name,
                                strlen(intf_ctrl.if_name)+1);
    }


    /* Even if kernel STP State Update fails, continue
     * as it is not important enough to halt the system
     */
    if (nl_int_update_stp_state(og.get()) != STD_ERR_OK) {
        NAS_STG_LOG(DEBUG, "Failed to updated kernel STP state to %d for interface index %d",
                state, intfindex);
        return true;
    }

    NAS_STG_LOG(DEBUG, "Updated the kerenl STP State to %d for interface index  %d", state,
            intfindex);
    return true;
}

// Get the default stg entry for the default switch
static bool nas_stg_get_default_entry(nas_stg_entry_t **entry) {
    auto default_stg_it = switch_to_default_stg_map->find(default_switch_id);
    if (default_stg_it == switch_to_default_stg_map->end()) {
        NAS_STG_LOG(ERR, "No default switch id exist");
        return false;
    }
    auto stg_table_it = nas_stg_table->find(default_stg_it->second);
    if (stg_table_it == nas_stg_table->end()) {
        NAS_STG_LOG(ERR, "No Default STG Entry exist");
        return false;
    }
    *entry = &(stg_table_it->second);
    return true;
}


// Get the default NDI Id for a given switch id and npu id
static bool nas_stg_get_default_ndi_id(nas_switch_id_t sid, npu_id_t npu_id, ndi_stg_id_t *ndi_id){
    auto it = switch_to_default_stg_map->find(sid);
    if (it == switch_to_default_stg_map->end()) {
        NAS_STG_LOG(ERR, "No switch id %d exist", sid);
        return false;
    }

    auto sit = nas_stg_table->find(it->second);
    if (sit == nas_stg_table->end()) {
        NAS_STG_LOG(ERR, "No Entry id %d exist", it->second);
        return false;
    }

    nas_stg_entry_t & entry = sit->second;
    auto nit = entry.npu_to_stg_map.find(npu_id);
    if (nit == entry.npu_to_stg_map.end()) {
        NAS_STG_LOG(ERR, "No Npu id %d exist", npu_id);
        return false;
    }

    *ndi_id = nit->second;
    return true;
}


t_std_error nas_stg_update_stg_state(hal_ifindex_t bid, hal_ifindex_t intfindex,
                                     unsigned int os_state) {

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);

    auto it = from_os_stp_state->find((os_stp_state_t)os_state);
    if( it == from_os_stp_state->end()){
        NAS_STG_LOG(ERR,"Invalid STP State received %d",os_state);
        return STD_ERR(STG,PARAM,0);
    }
    BASE_STG_INTERFACE_STATE_t state = it->second;
    /* In kernel when ports are added to bridge they will be always disabled if bridge is admin
     * down or in forwarding state if bridge is admin up. In that case don't create a new stg
     * instance.
     */

    if (state != BASE_STG_INTERFACE_STATE_DISABLED &&
        state != BASE_STG_INTERFACE_STATE_FORWARDING){
        if (!nas_stg_create_for_bridge(bid)) {
            return STD_ERR(STG, FAIL, 0);
        }
    }

    nas_stg_entry_t *entry;

    auto vit = bridge_to_vlan_map.find(bid);

    //If Bridge does not have a VLAN then use default entry
    if (vit != bridge_to_vlan_map.end()) {

        auto sit = vlan_to_stg_map.find(vit->second);

        // If vlan has an STG instance associated use that entry else use default entry
        if (sit != vlan_to_stg_map.end()) {
            auto stg_table_it = nas_stg_table->find(sit->second);
            if (stg_table_it == nas_stg_table->end()) {
                NAS_STG_LOG(ERR, "No STG Entry with bridge index %d and ID %d exist", bid,
                        sit->second);
                return STD_ERR(STG, NEXIST, 0);
            }
            entry = &(stg_table_it->second);
        } else {
            if (!nas_stg_get_default_entry(&entry))
                return STD_ERR(STG, FAIL, 0);
        }
    } else {
        if (!nas_stg_get_default_entry(&entry))
            return STD_ERR(STG, FAIL, 0);
    }

    // If entry has multiple vlans skip the update
    if((entry->vlan_list.size()>1) || (entry->cps_created == true)){
        NAS_STG_LOG(DEBUG, "Skipping kernel update as stg instance has more "
                    "than one vlans mapped to it or created via CPS ");
        return STD_ERR_OK;
    }

    if (!nas_update_stp_state(entry, intfindex, state))
        return STD_ERR(STG, FAIL, 0);

    return STD_ERR_OK;
}

static bool nas_stg_update_intf_info(nas_stg_entry_t * entry, cps_api_object_t obj,
                                     const cps_api_object_it_t & it) {

    cps_api_object_it_t it_lvl_1 = it;
    cps_api_attr_id_t ids[3] = { BASE_STG_ENTRY_INTF, 0 , BASE_STG_ENTRY_INTF_STATE };
    const int ids_len = sizeof(ids) / sizeof(ids[0]);
    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        ids[1] = cps_api_object_attr_id (it_lvl_1.attr);
        ids[2] = BASE_STG_ENTRY_INTF_STATE;
        cps_api_object_attr_t stp_state_attr = cps_api_object_e_get(obj, ids, ids_len);
        ids[2] = BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
        cps_api_object_attr_t ifindex_attr = cps_api_object_e_get(obj, ids, ids_len);
        ids[2] = BASE_STG_ENTRY_INTF_IF_NAME_IFNAME;
        cps_api_object_attr_t ifname_attr = cps_api_object_e_get(obj, ids, ids_len);

        if ((ifindex_attr == nullptr && ifname_attr == nullptr)  || stp_state_attr == nullptr) {
            NAS_STG_LOG(ERR,"Missing Necessary parameters for setting interface STP state");
            return false;
        }

        hal_ifindex_t ifindex;
        if(ifindex_attr){
            ifindex = cps_api_object_attr_data_u32(ifindex_attr);
        }else{
            auto * ifname = (const char *)cps_api_object_attr_data_bin(ifname_attr);
            interface_ctrl_t i;
            memset(&i,0,sizeof(i));
            strncpy(i.if_name,ifname,sizeof(i.if_name)-1);
            i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
                EV_LOGGING(NAS_L2, DEBUG, "NAS-STG","Can't get interface control information for %s",
                            ifname);
                    return false;
                }
            ifindex = i.if_index;
        }
        BASE_STG_INTERFACE_STATE_t stp_state = (BASE_STG_INTERFACE_STATE_t)
                                                cps_api_object_attr_data_u32(stp_state_attr);

        if (!nas_update_stp_state(entry, ifindex, stp_state)){
            return false;
        }

        for(auto var = entry->vlan_list.begin();var != entry->vlan_list.end();++var){
            if(!nas_stg_update_os_stp_state(ifindex, stp_state, *var, false)){
                return false;
            }
        }
    }
    return true;
}

static bool nas_stg_update_vlan_stp_state(nas_stg_entry_t * entry, hal_vlan_id_t id){
    for(auto it = entry->stp_states.begin();it != entry->stp_states.end();++it){
        if(!nas_stg_update_os_stp_state(it->first,it->second, id, false)){
            return false;
        }

        if(!nas_update_stp_state(entry,it->first,it->second)){
            return false;
        }

    }
    return true;
}

static bool nas_stg_update_vlan_member_stp_state(nas_stg_entry_t * entry, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex){

    auto it = entry->stp_states.find(ifindex);
    if(it == entry->stp_states.end()) return false;

    if(!nas_stg_update_os_stp_state(it->first,it->second, vlan_id, false)){
        return false;
    }

    if(!nas_update_stp_state(entry,it->first,it->second)){
        return false;
    }

    return true;
}

// Helper function to remove deleted vlans from vlan list and vlan to stg map
static void nas_stg_clean_vlan_list(nas_stg_vlan_list_t & cur_vlan_list,
        nas_stg_vlan_list_t & del_vlan_list) {
    for (auto it = del_vlan_list.begin(); it != del_vlan_list.end(); ++it) {
        cur_vlan_list.erase(*it);
    }
}


static bool nas_stg_delete_vlan(nas_stg_entry_t * entry, hal_vlan_id_t vlan_id){

    nas_stg_vlan_list_t del_vlan_list;
    ndi_stg_id_t ndi_id;
    nas_stg_entry_t *default_entry;
    if(!nas_stg_get_default_entry(&default_entry)){
        NAS_STG_LOG(ERR,"No Default STG Entry Exist");
        return false;
    }

    for (auto npu_it = entry->npu_to_stg_map.begin();
         npu_it != entry->npu_to_stg_map.end();
         ++npu_it) {

        if (!nas_stg_get_default_ndi_id(entry->switch_id, npu_it->first, &ndi_id)) {
            return false;
        }

        if (ndi_stg_update_vlan(npu_it->first, ndi_id, vlan_id) != STD_ERR_OK) {
            return false;
        }
    }
    entry->vlan_list.erase(vlan_id);
    default_entry->vlan_list.insert(vlan_id);
    vlan_to_stg_map[vlan_id] = default_entry->nas_stg_id;
    return true;
}

t_std_error nas_stg_delete_session(nas_stg_id_t id) {

    nas_stg_entry_t *default_entry;
    if(!nas_stg_get_default_entry(&default_entry)){
        NAS_STG_LOG(ERR,"No Default STG Entry Exist");
        return false;
    }

    NAS_STG_LOG(DEBUG,"Deleting STG instance %d",id);

    if(default_entry->nas_stg_id == id){
        NAS_STG_LOG(ERR,"Cannot deleted default STG instance");
        return STD_ERR(STG,FAIL,0);
    }
    nas_stg_table_it table_it = nas_stg_table->find(id);

    if (table_it != nas_stg_table->end()) {
        nas_stg_entry_t & entry = table_it->second;

        // Remove all the vlans associated with this stg id
        for (auto vit = entry.vlan_list.begin(); vit != entry.vlan_list.end();) {
            if(!nas_stg_delete_vlan(&entry, *vit)){
                NAS_STG_LOG(ERR,"Failed to delete STG id %d",id);
                return STD_ERR(STG,FAIL,0);
            }
            vit = entry.vlan_list.begin();
        }


        //Delete the STG id from all NPUs
        for (auto it = entry.npu_to_stg_map.begin(); it != entry.npu_to_stg_map.end(); ++it) {
            if (ndi_stg_delete(it->first, it->second) != STD_ERR_OK) {
                return STD_ERR(STG,FAIL,0);
            }
        }

        NAS_STG_LOG(DEBUG, "Deleted the STG Instance with ID %d", entry.nas_stg_id);
        nas_stg_remove_index(entry.nas_stg_id);
        nas_stg_table->erase(table_it);

    } else {
        NAS_STG_LOG(ERR,  "No STG instance with Id %d exist", id);
        return STD_ERR(STG, NEXIST, 0);
    }

    return STD_ERR_OK;
}




static bool nas_stg_add_vlan(nas_stg_entry_t * entry, hal_vlan_id_t vlan_id){

   for (auto npu_it = entry->npu_to_stg_map.begin();
        npu_it != entry->npu_to_stg_map.end();
        ++npu_it) {

       if (ndi_stg_update_vlan(npu_it->first, npu_it->second, vlan_id) != STD_ERR_OK) {
            return false;
       }
    }

   auto vlan_to_stg_it = vlan_to_stg_map.find(vlan_id);
   if (vlan_to_stg_it != vlan_to_stg_map.end()){
       auto stg_table_it = nas_stg_table->find(vlan_to_stg_it->second);
       if(stg_table_it == nas_stg_table->end()){
           NAS_STG_LOG(ERR,"No STG entry %d exist",vlan_to_stg_it->second);
           return false;
       }
       nas_stg_entry_t & old_entry = stg_table_it->second;
       old_entry.vlan_list.erase(vlan_id);
   }

   vlan_to_stg_map[vlan_id] = entry->nas_stg_id;
   entry->vlan_list.insert(vlan_id);
   nas_stg_update_vlan_stp_state(entry,vlan_id);
   return true;
}


/* Updates the vlan list, removes the existing vlans not in the new list and add new vlans which
 * are not in the existing vlan list
 */
static bool nas_stg_update_vlan_list(nas_stg_entry_t * entry, nas_stg_vlan_list_t & vlan_list) {
    nas_stg_vlan_list_t del_vlan_list;

    //If existing VLAN is not in the new list remove it else remove it from the new list
    for (auto it = entry->vlan_list.begin(); it != entry->vlan_list.end();) {
        if (vlan_list.find(*it) == vlan_list.end()) {
            hal_vlan_id_t vlan_id = *it;
            if(!nas_stg_delete_vlan(entry,vlan_id)){
                return false;
            }
            it = entry->vlan_list.begin();
            del_vlan_list.insert(vlan_id);
        } else {
            vlan_list.erase(*it);
            ++it;
        }
    }

    nas_stg_clean_vlan_list(entry->vlan_list, del_vlan_list);

    // Add remaining VLANs in the new list
    for (auto it = vlan_list.begin(); it != vlan_list.end(); ++it) {

        if (entry->vlan_list.find(*it) == entry->vlan_list.end()) {
           if(!nas_stg_add_vlan(entry,*it)){
               return false;
           }
        }
    }

    return true;
}


static bool nas_stg_update_entry(nas_stg_entry_t * entry, cps_api_object_t obj) {

    nas_stg_vlan_list_t add_vlan_list;
    bool update_stp_state = false;
    bool vlan_list_attr = false;
    cps_api_object_it_t it;
    cps_api_object_it_t intf_it;

    cps_api_object_it_begin(obj, &it);

    for (; cps_api_object_it_valid(&it); cps_api_object_it_next(&it)) {

        int id = (int) cps_api_object_attr_id(it.attr);
        uint32_t vlan_id;
        switch (id) {

        case BASE_STG_ENTRY_VLAN:
            vlan_list_attr = true;
            if (cps_api_object_attr_len(it.attr) != 0) {
                vlan_id = cps_api_object_attr_data_u32(it.attr);
                add_vlan_list.insert(vlan_id);
            }
            break;

        case BASE_STG_ENTRY_INTF:
            update_stp_state=true;
            memcpy(&intf_it,&it,sizeof(it));
            break;

        default:
            break;
        }
    }

    if (vlan_list_attr) {
        if (!nas_stg_update_vlan_list(entry, add_vlan_list)) {
            NAS_STG_LOG(ERR, "Failed to update vlan list");
            return false;
        }
    }

    if (update_stp_state) {
        if (!nas_stg_update_intf_info(entry, obj, intf_it)) {
            NAS_STG_LOG(ERR, "Error Updating STG interface state for STG instance %d",
                    entry->nas_stg_id);
            return false;
        }
    }

    return true;
}


t_std_error nas_stg_cps_create_instance(cps_api_object_t obj) {

    nas_stg_entry_t entry;
    entry.switch_id = 0;

    auto npu_it = switch_to_npu_map->find(entry.switch_id);
    if (npu_it == switch_to_npu_map->end()) {
        NAS_STG_LOG(ERR, "No such switch ID %d exist", entry.switch_id);
        return STD_ERR(STG, NEXIST, 0);
    }

    nas_stg_npu_ids & npu_ids = npu_it->second;
    ndi_stg_id_t ndi_stg_id;

    //Create new STG instance in all the NPUs
    for (auto it = npu_ids.begin(); it != npu_ids.end(); ++it) {
        if (ndi_stg_add(*it, &ndi_stg_id) != STD_ERR_OK) {
            return STD_ERR(STG, FAIL, 0);
        }
        entry.npu_to_stg_map.insert(npu_to_stg_map_pair(*it, ndi_stg_id));
    }

    {
        std_mutex_simple_lock_guard lock(&nas_stg_mutex);
        entry.nas_stg_id = nas_stg_get_next_index();
        entry.cps_created = true;
        cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                  &entry.nas_stg_id,sizeof(entry.nas_stg_id));
        nas_stg_table->insert(nas_stg_table_pair(entry.nas_stg_id, std::move(entry)));
        NAS_STG_LOG(DEBUG, "Created new STG Entry with id %d", entry.nas_stg_id);
    }
    return nas_stg_set_instance(obj, entry.nas_stg_id);
}


t_std_error nas_stg_set_instance(cps_api_object_t obj, nas_stg_id_t stg_id) {

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    NAS_STG_LOG(DEBUG,"Updating STG id %d",stg_id);
    nas_stg_table_it it = nas_stg_table->find(stg_id);
    if (it == nas_stg_table->end()) {
        NAS_STG_LOG(ERR,  "No STG id %d exist", stg_id);
        return STD_ERR(STG, NEXIST, 0);
    }

    if (!nas_stg_update_entry(&(it->second), obj)) {
        return STD_ERR(STG, FAIL, 0);
    }

    return STD_ERR_OK;
}


t_std_error nas_stg_cps_delete_instance(nas_stg_id_t stg_id) {
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    return nas_stg_delete_session(stg_id);
}


t_std_error nas_stg_add_vlan_to_bridge(hal_ifindex_t bid, hal_vlan_id_t vlan_id) {

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);

    auto it = bridge_to_vlan_map.find(bid);
    const hal_vlan_id_t default_vlan = 1;
    if (it == bridge_to_vlan_map.end()) {
        bridge_to_vlan_map[bid] =  (vlan_id == 0 ? default_vlan : vlan_id);
        NAS_STG_LOG(DEBUG,  "Adding Bridge %d to VLAN with id %d", bid, vlan_id == 0 ? default_vlan : vlan_id );
    } else {
        NAS_STG_LOG(DEBUG,  "Already vlan exist with bridge id %d", bid);
        return STD_ERR(STG, PARAM, 0);
    }
    return STD_ERR_OK;
}

t_std_error nas_stg_delete_instance(hal_ifindex_t bid) {

    t_std_error rc;
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    nas_br_to_stg_map_it it = bridge_to_stg_map->find(bid);

    if (it != bridge_to_stg_map->end()) {
        if ((rc = nas_stg_delete_session(it->second)) != STD_ERR_OK) {
            return rc;
        }
        bridge_to_stg_map->erase(it);
        auto vit = bridge_to_vlan_map.find(bid);
        if (vit != bridge_to_vlan_map.end()) {
            auto stg_it = vlan_to_stg_map.find(vit->second);
            if (stg_it != vlan_to_stg_map.end()) {
                vlan_to_stg_map.erase(stg_it);
            }
            bridge_to_vlan_map.erase(vit);
        }
    } else {
        NAS_STG_LOG(ERR,  "No Bridge with id %d exist in the STG table", bid);
        return STD_ERR(STG, NEXIST, 0);
    }

    return STD_ERR_OK;
}


static void nas_stg_fill_object(cps_api_object_t obj, nas_stg_table_it tit,
                                nas_stg_port_list_t* intf_list) {

    nas_stg_entry_t & entry = tit->second;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_STG_ENTRY_OBJ,
                                                     cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                              &entry.nas_stg_id,sizeof(entry.nas_stg_id));

    cps_api_object_attr_add_u32(obj, BASE_STG_ENTRY_ID, entry.nas_stg_id);

    if (entry.vlan_list.empty()) {
        cps_api_object_attr_add(obj, BASE_STG_ENTRY_VLAN, NULL, 0);
    } else {
        for (nas_stg_vlan_list_it vit = entry.vlan_list.begin(); vit != entry.vlan_list.end(); ++vit) {
            cps_api_object_attr_add_u32(obj, BASE_STG_ENTRY_VLAN, (*vit));
        }
    }

    if (intf_list != NULL) {
        cps_api_attr_id_t ids[3] = {BASE_STG_ENTRY_INTF, 0, BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX};
        const int ids_len = sizeof(ids) / sizeof(ids[0]);
        cps_api_attr_id_t list_index = 0;
        uint32_t ifindex;
        interface_ctrl_t intf_ctrl;
        BASE_STG_INTERFACE_STATE_t stp_state;
        for (auto& val: *intf_list) {
            ifindex = (uint32_t)val;
            ids[1] = list_index;
            memset(&intf_ctrl, 0, sizeof(intf_ctrl));
            if (!nas_stg_intf_to_port(ifindex, &intf_ctrl)) {
                continue;
            }
            if (ndi_stg_get_stp_port_state(intf_ctrl.npu_id,
                        entry.npu_to_stg_map.find(intf_ctrl.npu_id)->second,
                        intf_ctrl.port_id, &stp_state) != STD_ERR_OK) {
                continue;
            }
            ids[2] = BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
            cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_U32,
                                 &ifindex, sizeof(uint32_t));
            ids[2] = BASE_STG_ENTRY_INTF_STATE;
            cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_U32,
                                 &stp_state, sizeof(uint32_t));
            list_index ++;
        }
    }
}


t_std_error nas_stg_get_all_info(cps_api_object_list_t list) {

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);

    for (nas_stg_table_it tit = nas_stg_table->begin(); tit != nas_stg_table->end(); ++tit) {

        cps_api_object_t obj = cps_api_object_list_create_obj_and_append(list);
        if (obj == NULL) {
            NAS_STG_LOG(ERR, "Failed to create/append new object to list");
            return STD_ERR(STG, NOMEM, 0);
        }

        nas_stg_fill_object(obj, tit, NULL);
    }

    return STD_ERR_OK;
}


t_std_error nas_stg_get_instance_info(cps_api_object_list_t list, nas_stg_id_t id,
                                      nas_stg_port_list_t* intf_list) {

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    nas_stg_table_it tit = nas_stg_table->find(id);

    if (tit != nas_stg_table->end()) {
        cps_api_object_t obj = cps_api_object_list_create_obj_and_append(list);
        if (obj == NULL) {
            NAS_STG_LOG(ERR, "Failed to create/append new object to list");
            return STD_ERR(STG, NOMEM, 0);
        }

        nas_stg_fill_object(obj, tit, intf_list);
    } else {
        NAS_STG_LOG(ERR, "No STG instance %d exist", id);
        return STD_ERR(STG, NEXIST, 0);
    }

    return STD_ERR_OK;
}


/*
 * Get the default stg id from NPU for all the switches and all the npus in a switch
 * created a default NAS STG entry for each switch
 */
t_std_error nas_stg_create_default_instance() {

    t_std_error rc;

    ndi_stg_id_t ndi_stg_id;

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);


    auto npu_it = switch_to_npu_map->begin();
    if (npu_it == switch_to_npu_map->end()) {
        NAS_STG_LOG(ERR, "No switch ID exist");
        return STD_ERR(STG, NEXIST, 0);
    }

    hal_vlan_id_t vlan_id;
    // For each switch create a new entry
    for (; npu_it != switch_to_npu_map->end(); ++npu_it) {
        nas_stg_entry_t entry;
        nas_stg_npu_ids & npu_ids = npu_it->second;

        // For each npu in the switch get the default STG id from npu
        for (auto it = npu_ids.begin(); it != npu_ids.end(); ++it) {
            if ((rc = ndi_stg_get_default_id(*it, &ndi_stg_id,&vlan_id)) != STD_ERR_OK)
                return rc;
            entry.npu_to_stg_map.insert(npu_to_stg_map_pair(*it, ndi_stg_id));
        }

        entry.nas_stg_id = nas_stg_get_next_index();
        switch_to_default_stg_map->insert(
                nas_stg_switch_defult_stg_map_pair_t(npu_it->first, entry.nas_stg_id));
        entry.switch_id = npu_it->first;
        entry.vlan_list.insert(vlan_id);
        entry.cps_created = true;
        vlan_to_stg_map[vlan_id] = entry.nas_stg_id;
        nas_stg_table->insert(nas_stg_table_pair(entry.nas_stg_id, std::move(entry)));
        NAS_STG_LOG(DEBUG, "Created Default STG Instance with Id %d for switch id %d ",
        entry.nas_stg_id,entry.switch_id);
    }

    return STD_ERR_OK;
}


//Construct a map of list of switches and its npu ids
t_std_error nas_stg_get_npu_list(void) {

    const nas_switches_t * switches = nas_switch_inventory();

    for (size_t ix = 0; ix < switches->number_of_switches; ++ix) {

        const nas_switch_detail_t * sd = nas_switch((nas_switch_id_t) ix);
        if (sd == NULL) {
            NAS_STG_LOG(ERR,"Switch Details Configuration file is erroneous");
            return STD_ERR(STG, PARAM, 0);
        }

        nas_stg_npu_ids npus;
        for (size_t sd_ix = 0; sd_ix < sd->number_of_npus; ++sd_ix) {
            npus.insert(sd->npus[sd_ix]);
        }

        switch_to_npu_map->insert(
                nas_stg_switch_npu_pair_t(switches->switch_list[ix], std::move(npus)));
    }

    return STD_ERR_OK;
}


t_std_error nas_stg_get_default_instance(cps_api_object_list_t list){

    static const nas_switch_id_t nas_switch_id = 0;
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    auto it = switch_to_default_stg_map->find(nas_switch_id);
    if (it == switch_to_default_stg_map->end()) {
        NAS_STG_LOG(ERR, "No switch id %d exist", nas_switch_id);
        return STD_ERR(STG,NEXIST,0);
    }

    cps_api_object_t ret_obj = cps_api_object_list_create_obj_and_append(list);
    if (ret_obj == NULL) {
        NAS_STG_LOG(ERR,"Failed to create/append new object to list");
        return STD_ERR(STG, NOMEM, 0);
    }

    cps_api_object_attr_add_u32(ret_obj, BASE_STG_DEFAULT_STG_ID, it->second);
    return STD_ERR_OK;
}


t_std_error nas_stg_vlan_update(hal_vlan_id_t id,bool add,hal_ifindex_t bridge_index){

    nas_stg_entry_t *entry;
    if (!nas_stg_get_default_entry(&entry)){
        return STD_ERR(STG, FAIL, 0);
    }

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    if(add){
        NAS_STG_LOG(DEBUG,"Adding VLAN %d to Bridge %d",id,bridge_index);
        bridge_to_vlan_map[bridge_index] = id;
        auto it = vlan_to_stg_map.find(id);
        if( it == vlan_to_stg_map.end()){
            vlan_to_stg_map[id] = entry->nas_stg_id;
            entry->vlan_list.insert(id);
            nas_stg_update_vlan_stp_state(entry,id);
            NAS_STG_LOG(DEBUG,"Added vlan id %d to default instance",id);
        }else{
            auto sit = nas_stg_table->find(it->second);
            if(sit == nas_stg_table->end()) return STD_ERR(STG,FAIL,0);
            nas_stg_entry_t * entry = &(sit->second);
            nas_stg_update_vlan_stp_state(entry,id);
            NAS_STG_LOG(DEBUG,"vlan id %d already part of instance %d",id,it->second);
        }
    }else{
        bridge_to_vlan_map.erase(bridge_index);
        auto it = vlan_to_stg_map.find(id);
        if( it == vlan_to_stg_map.end()){
            NAS_STG_LOG(DEBUG,"No STG instance for vlan %d exsist",id);
        }else{
            NAS_STG_LOG(DEBUG,"Removing VLAN %d from Bridge %d",id,bridge_index);
            auto sit = nas_stg_table->find(it->second);
            nas_stg_entry_t * entry = &(sit->second);
            entry->vlan_list.erase(id);
            vlan_to_stg_map.erase(id);
            NAS_STG_LOG(DEBUG,"Deleting VLAN %d from STG instance %d",id,it->second);
        }
    }

    return STD_ERR_OK;
}


t_std_error nas_stg_update_vlans(cps_api_object_t obj, nas_stg_id_t id,bool add){

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    auto sit = nas_stg_table->find(id);
    if (sit == nas_stg_table->end()){
        NAS_STG_LOG(ERR,"No STG Id %d exist to update vlans",id);
        return STD_ERR(STG,NEXIST,0);
    }
    nas_stg_vlan_list_t del_vlan_list;
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj, &it);

    for (; cps_api_object_it_valid(&it); cps_api_object_it_next(&it)) {

        switch (cps_api_object_attr_id(it.attr)) {

           case BASE_STG_ENTRY_VLAN:
               if(add){
                   if(!nas_stg_add_vlan(&(sit->second),cps_api_object_attr_data_u32(it.attr))){
                       return STD_ERR(STG,FAIL,0);
                   }
               }else{
                   if(!nas_stg_delete_vlan(&(sit->second),cps_api_object_attr_data_u32(it.attr))){
                       return STD_ERR(STG,FAIL,0);
                   }
               }
               break;

           default:
               break;
        }
    }

    return STD_ERR_OK;
}


static bool nas_stg_lag_handle_port_delete(hal_ifindex_t lag_index,nas_lag_port_list_t  & del_port_list){
    for (auto tit = nas_stg_table->begin(); tit != nas_stg_table->end(); ++tit) {
        nas_stg_entry_t & entry = tit->second;
        auto lag_stp_it = entry.stp_states.find(lag_index);
        interface_ctrl_t intf_ctrl;
        if(lag_stp_it != entry.stp_states.end()){
            for(auto del_it = del_port_list.begin(); del_it != del_port_list.end();++del_it){
                memset(&intf_ctrl,0,sizeof(intf_ctrl));
                if (!nas_stg_intf_to_port(*del_it, &intf_ctrl)) {
                    return false;
                }

                if (ndi_stg_set_stp_port_state(intf_ctrl.npu_id,
                            entry.npu_to_stg_map.find(intf_ctrl.npu_id)->second,
                            intf_ctrl.port_id,BASE_STG_INTERFACE_STATE_BLOCKING) != STD_ERR_OK) {
                    return false;
                }

                entry.stp_states[*del_it]=BASE_STG_INTERFACE_STATE_BLOCKING;
            }
        }
    }
    return true;
}


static bool nas_stg_lag_set(hal_ifindex_t lag_index, cps_api_object_t obj){
    auto it = nas_lag_map->find(lag_index);
    if(it == nas_lag_map->end()){
        NAS_STG_LOG(DEBUG,"No Lag Interface Index %d exist in map",lag_index);
        return false;
    }

    nas_lag_port_list_t * port_list = &(it->second);
    nas_lag_port_list_t update_port_list;

    cps_api_object_it_t obj_it;
    cps_api_object_it_begin(obj,&obj_it);

    for ( ; cps_api_object_it_valid(&obj_it) ; cps_api_object_it_next(&obj_it) ) {

        switch (cps_api_object_attr_id(obj_it.attr)) {
        case DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS:
            if(cps_api_object_attr_len(obj_it.attr) != 0){
                update_port_list.insert(cps_api_object_attr_data_u32(obj_it.attr));
            }
            break;
        default :
            NAS_STG_LOG(DEBUG,"Unknown Attribute %lu for LAG",
                        cps_api_object_attr_id(obj_it.attr));
            break;
        }
    }

    /* Iterate through the old port list and see if it is there in the
     * new list then remove it from existing list
     */
    for( auto port_it = port_list->begin() ; port_it != port_list->end(); ){
        if(update_port_list.find(*port_it) != update_port_list.end()){
            port_list->erase(port_it++);
        }else{
            ++port_it;
        }
    }

    /*
     * set the port state to blocking for ports which are removed from lag
     */
    if(port_list->size() > 0 )
    {
        nas_stg_lag_handle_port_delete(lag_index,*port_list);
    }

    // Set the new member port list for the lag
    it->second = update_port_list;

    for (auto tit = nas_stg_table->begin(); tit != nas_stg_table->end(); ++tit) {
       nas_stg_entry_t & entry = tit->second;
       auto lag_stp_it = entry.stp_states.find(lag_index);

       if(lag_stp_it != entry.stp_states.end()){

           /*
            * Check the stp state if there is already a stp state associated with the LAG
            * then apply that state to all members of LAG
            */

           NAS_STG_LOG(INFO,"Setting stp state to %d for new lag member",lag_stp_it->second);
           if(!nas_update_stp_state(&entry,lag_index,lag_stp_it->second)){
               return STD_ERR(STG,FAIL,0);
           }

           for(auto var = entry.vlan_list.begin();var != entry.vlan_list.end();++var){
               if(!nas_stg_update_os_stp_state(lag_index, lag_stp_it->second, *var, false)){
                   return false;
               }
           }
       }
    }

    return true;
}

t_std_error nas_stg_lag_update(hal_vlan_id_t id, bool create){

    return STD_ERR_OK;
}


bool nas_stg_lag_cleanup(hal_ifindex_t lag_index){

    for (auto tit = nas_stg_table->begin(); tit != nas_stg_table->end(); ++tit) {
        nas_stg_entry_t & entry = tit->second;
        auto lag_stp_it = entry.stp_states.find(lag_index);

        if(lag_stp_it != entry.stp_states.end()){

            NAS_STG_LOG(INFO,"Setting stp state to %d for deleted lag member",
                        BASE_STG_INTERFACE_STATE_BLOCKING);
            if(!nas_update_stp_state(&entry,lag_index,BASE_STG_INTERFACE_STATE_BLOCKING)){
                return false;
            }

            entry.stp_states.erase(lag_index);
        }
    }
    return true;
}


t_std_error nas_stg_lag_update(hal_ifindex_t lag_index, cps_api_object_t obj){
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    auto it = nas_lag_map->find(lag_index);

    if(op == cps_api_oper_CREATE) {
        if (it == nas_lag_map->end()){
            nas_lag_port_list_t port_list;
            nas_lag_map->insert(nas_stg_lag_pair(lag_index,std::move(port_list)));
        }else{
            NAS_STG_LOG(DEBUG,"Lag Interface Index %d already exist in map",lag_index);
        }
    }
    else if (op == cps_api_oper_DELETE) {
        if (it != nas_lag_map->end()){
            /*
             * reset the port states to blocking when port-channel is deleted
             */
            nas_stg_lag_cleanup(lag_index);
            nas_lag_map->erase(it);
        }else{
            NAS_STG_LOG(ERR,"No Lag Interface Index %d exist in map",lag_index);
            return STD_ERR(STG,NEXIST,0);
        }
    }
    else if (op == cps_api_oper_SET) {
        if(!nas_stg_lag_set(lag_index, obj)){
            return STD_ERR(STG,FAIL,0);
        }
    }
    return STD_ERR_OK;
}

t_std_error nas_stg_set_default_instance_state(cps_api_object_t obj){

    std_mutex_simple_lock_guard lock(&nas_stg_mutex);

    cps_api_object_attr_t def_state_attr;
    if ((def_state_attr = cps_api_object_attr_get(obj,BASE_STG_DEFAULT_STG_STATE)) == NULL) {
        NAS_STG_LOG(ERR,"No default stp state passed");
        return (cps_api_return_code_t)STD_ERR(STG,CFG,0);
    }
    default_stg_state =(BASE_STG_INTERFACE_STATE_t) cps_api_object_attr_data_u32(def_state_attr);

    nas_stg_entry_t *entry;
    if(nas_stg_get_default_entry(&entry)){
        for(auto it : entry->npu_to_stg_map){
            if(ndi_stg_set_all_stp_port_state(it.first,it.second,default_stg_state) != STD_ERR_OK){
                   EV_LOGGING(NAS_L2,ERR,"NAS-STG","Failed to set default STG state");
                   return STD_ERR(STG,FAIL,0);
            }
        }
    }else{
        return STD_ERR(STG,FAIL,0);
    }
    EV_LOGGING(NAS_L2,DEBUG,"NAS-STG","Set the port states to %d in default state",default_stg_state);
    return STD_ERR_OK;
}


t_std_error nas_stg_set_interface_default_state(npu_id_t npu,port_t port){
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);

    nas_stg_entry_t *entry;
    if(nas_stg_get_default_entry(&entry)){
        for(auto it : entry->npu_to_stg_map){
            if(ndi_stg_set_stp_port_state(it.first,it.second,port,default_stg_state) != STD_ERR_OK){
                EV_LOGGING(NAS_L2,ERR,"NAS-STG","Failed to set default STG state for port %d",port);
                return STD_ERR(STG,FAIL,0);
            }
        }
    }else{
        return STD_ERR(STG,FAIL,0);
    }
    EV_LOGGING(NAS_L2,DEBUG,"NAS-STG","Set the port state for %d to %d in default state",port,default_stg_state);
    return STD_ERR_OK;
}

t_std_error nas_stg_set_vlan_member_port_state(hal_vlan_id_t vlan_id, hal_ifindex_t ifindex){
    std_mutex_simple_lock_guard lock(&nas_stg_mutex);
    auto it = vlan_to_stg_map.find(vlan_id);
    if( it != vlan_to_stg_map.end()){

        auto sit = nas_stg_table->find(it->second);
        if(sit == nas_stg_table->end()) return STD_ERR(STG,FAIL,0);
        nas_stg_entry_t * entry = &(sit->second);
        nas_stg_update_vlan_member_stp_state(entry,vlan_id,ifindex);
    }
    return STD_ERR_OK;
}
