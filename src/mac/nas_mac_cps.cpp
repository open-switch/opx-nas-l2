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
 * filename: nas_mac_cps.cpp
 */

#include "dell-base-l2-mac.h"
#include "dell-base-if-lag.h"
#include "dell-base-if-phy.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"

#include "dell-base-common.h"
#include "nas_mac_api.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "std_error_codes.h"
#include "std_utils.h"
#include "nas_ndi_mac.h"
#include "nas_ndi_switch.h"
#include "hal_if_mapping.h"
#include "cps_api_interface_types.h"
#include "std_thread_tools.h"
#include "ds_common_types.h"
#include "std_mac_utils.h"
#include "dell-base-routing.h"
#include "os-routing-events.h"
#include "bridge-model.h"

#include "cps_api_object.h"
#include "cps_api_object_key.h"
#include "std_socket_tools.h"

#include <unordered_map>
#include <unordered_set>

static bool mac_auto_flush=true;

static int cps_thread_fd[2];
static int npu_thread_fd[2];

// map to maintain vlan id to bridge ifindex mapping
static auto mac_vlan_id_to_ifindex_map = new std::unordered_map<hal_vlan_id_t,hal_ifindex_t>;


// map to maintain interface ifindex to list of bridge index mapping
static auto mac_port_to_vlan_id_map = new std::unordered_map<hal_ifindex_t,std::unordered_set<hal_ifindex_t>>;

//map to maintain parent_bridge_port index to vlan_id
static auto map_parent_br_to_vlan_id =new std::unordered_map<hal_ifindex_t ,hal_vlan_id_t>;

/* 0 means it is not set */
static hal_vlan_id_t bridge_1d_default_untag_vid = 0;

static std_mutex_lock_create_static_init_fast(nas_mac_mutex);

/* Mutex for  map_parent_br_to_vlan_id , bridge_1d_default_untag_vid */

static std_mutex_lock_create_static_init_fast(untagged_vlan_id_mutex);


bool nas_mac_get_1d_br_untag_vid(hal_ifindex_t ifx, hal_vlan_id_t &vlan_id) {

   std_mutex_simple_lock_guard lock(&untagged_vlan_id_mutex);
   auto it = map_parent_br_to_vlan_id->find(ifx);
   if (it == map_parent_br_to_vlan_id->end()) {
       vlan_id = bridge_1d_default_untag_vid;
   } else {
       vlan_id = it->second;
   }
   NAS_MAC_LOG(DEBUG ,"Untagged VLAN id for 1d bridge idx %d is %d ", ifx, vlan_id);
   return true;

}

bool nas_mac_publish_flush_event(ndi_mac_delete_type_t del_type, nas_mac_entry_t * entry){
    cps_api_object_t obj  = cps_api_object_create();
    if(!obj) return false;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_MAC_FLUSH_EVENT_OBJ,cps_api_qualifier_OBSERVED);
    std_mutex_simple_lock_guard lock(&nas_mac_mutex);

    /*
     * For vlan and or port flush get the bridge index from
     * the map and publish bridge index for vlan id
    */
    size_t index = 0;
    cps_api_attr_id_t ids[3] = {BASE_MAC_FLUSH_EVENT_FILTER, index,BASE_MAC_FLUSH_EVENT_FILTER_MEMBER_IFINDEX };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    if(del_type == NDI_MAC_DEL_BY_PORT_VLAN || del_type == NDI_MAC_DEL_BY_VLAN){
        if(mac_vlan_id_to_ifindex_map->find(entry->entry_key.vlan_id) != mac_vlan_id_to_ifindex_map->end()){
            hal_ifindex_t ifindex = mac_vlan_id_to_ifindex_map->at(entry->entry_key.vlan_id);
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,sizeof(ifindex));
            ids[2] = BASE_MAC_FLUSH_EVENT_FILTER_VLAN;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U16,&entry->entry_key.vlan_id,
                                 sizeof(entry->entry_key.vlan_id));

            if(del_type == NDI_MAC_DEL_BY_PORT_VLAN){
                ids[2] = BASE_MAC_FLUSH_EVENT_FILTER_IFINDEX;
                cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&entry->ifindex,sizeof(entry->ifindex));
            }
        }
    }
    /*
     * For port flush find the list of bridge indexes this port
     * is part of and send that list
    */
    if(del_type == NDI_MAC_DEL_BY_PORT){
        ids[2] = BASE_MAC_FLUSH_EVENT_FILTER_IFINDEX;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&entry->ifindex,sizeof(entry->ifindex));
        auto it = mac_port_to_vlan_id_map->find(entry->ifindex);
        if(it != mac_port_to_vlan_id_map->end()){
            ids[2] = BASE_MAC_FLUSH_EVENT_FILTER_MEMBER_IFINDEX;
            for (auto ifindex : it->second){
                cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,sizeof(ifindex));
            }
        }
    }

    if(del_type == NDI_MAC_DEL_ALL_ENTRIES){
        ids[2]= BASE_MAC_FLUSH_EVENT_FILTER_ALL;
        bool flush_all = true;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,&flush_all,sizeof(flush_all));
    }
    nas_mac_event_publish(obj);
    return true;

}


int nas_mac_get_read_cps_thread_fd(){
    return cps_thread_fd[0];
}

int nas_mac_get_write_cps_thread_fd(){
    return cps_thread_fd[1];
}

int nas_mac_get_read_npu_thread_fd(){
    return npu_thread_fd[0];
}

int nas_mac_get_write_npu_thread_fd(){
    return npu_thread_fd[1];
}

static void nas_mac_entry_to_cps_obj(cps_api_object_list_t list, nas_mac_entry_t & entry){
    cps_api_object_t obj= cps_api_object_list_create_obj_and_append(list);
    if (!obj) {
        return;
    }
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_VLAN, entry.entry_key.vlan_id);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_IFINDEX, entry.ifindex);
    cps_api_object_attr_add(obj,BASE_MAC_QUERY_MAC_ADDRESS, entry.entry_key.mac_addr,
                            sizeof(hal_mac_addr_t));
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_ACTIONS, entry.pkt_action);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_STATIC, entry.is_static);

    return;

}
static cps_api_return_code_t cps_nas_mac_get_function (void * context, cps_api_get_params_t * param, size_t ix) {

    nas_mac_entry_t mac_entry;

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if(filt){
        cps_api_object_attr_t mac_attr = cps_api_object_attr_get(filt,BASE_MAC_QUERY_MAC_ADDRESS);
        cps_api_object_attr_t vlan_attr = cps_api_object_attr_get(filt,BASE_MAC_QUERY_VLAN);
        if(!mac_attr || !vlan_attr){
            NAS_MAC_LOG(ERR,"MAC and VLAN is required to do get of MAC entry");
            return cps_api_ret_code_ERR;
        }

        mac_entry.entry_key.vlan_id = cps_api_object_attr_data_u16(vlan_attr);
        memcpy(&mac_entry.entry_key.mac_addr, cps_api_object_attr_data_bin(mac_attr), cps_api_object_attr_len(mac_attr));
        if(nas_get_mac_entry_from_ndi(mac_entry)){
            nas_mac_entry_to_cps_obj(param->list,mac_entry);
            return cps_api_ret_code_OK;
        }
    }

    return cps_api_ret_code_ERR;
}


static cps_api_return_code_t cps_nas_mac_set_function(void * context, cps_api_transaction_params_t * param, size_t ix) {

    t_std_error rc;

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if( op == cps_api_oper_CREATE){
        if ((rc = nas_mac_cps_create_entry(obj))!= STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if ( op == cps_api_oper_CREATE || op == cps_api_oper_DELETE) {
        cps_api_object_t cloned = cps_api_object_create();
        cps_api_object_clone(cloned, obj);
        cps_api_object_list_append(param->prev, cloned);
    }

    if(op == cps_api_oper_DELETE ) {
        if((rc = nas_mac_cps_delete_entry(obj)) != STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    if( op == cps_api_oper_SET){
        NAS_MAC_LOG(DEBUG,  "in update/set request handling ");
        if((rc = nas_mac_cps_update_entry(obj)) != STD_ERR_OK) {
            return (cps_api_return_code_t)rc;
        }
    }

    return cps_api_ret_code_OK;
}




static cps_api_return_code_t nas_mac_flush_handler (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Invalid operation %d for flusing macs",op);
        return (cps_api_return_code_t)STD_ERR(MAC,PARAM,0);
    }

    if(nas_mac_cps_flush_entry(obj)!= STD_ERR_OK){
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Failed to flush entries");
        return (cps_api_return_code_t)STD_ERR(MAC,FAIL,0);
    }

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_mac_flush_mgmt_set(void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_object_attr_t auto_flush_attr = cps_api_object_attr_get(obj,
                                        BASE_MAC_FLUSH_MANAGEMENT_ENABLE);

    if(auto_flush_attr == NULL){
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","No value passed to change auto mac management");
        return (cps_api_return_code_t)STD_ERR(MAC,FAIL,0);
    }

    mac_auto_flush = (bool)cps_api_object_attr_data_u32(auto_flush_attr);
    EV_LOGGING(L2MAC,DEBUG,"NAS-MAC","Auto MAC management value set to %d",mac_auto_flush);

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_mac_flush_mgmt_get(void * context, cps_api_get_params_t * param, size_t ix){

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(param->list);
    if (obj == NULL) {
        EV_LOGGING(L2MAC,ERR,"NAS-MAC","Failed to create/append new object to list");
        return (cps_api_return_code_t)STD_ERR(MAC, NOMEM, 0);
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_MAC_FLUSH_MANAGEMENT_OBJ,
                                                       cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj, BASE_MAC_FLUSH_MANAGEMENT_ENABLE, mac_auto_flush);

    return cps_api_ret_code_OK;
}


static t_std_error cps_nas_mac_init(cps_api_operation_handle_t handle) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(ERR, "Could not translate %d to key %s,", (int)(BASE_MAC_TABLE_OBJ),
                cps_api_key_print(&f.key, buff, sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    NAS_MAC_LOG(DEBUG, "Registering for BASE_MAC_TABLE_OBJ %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = handle;
    f._write_function = cps_nas_mac_set_function;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&f,0,sizeof(f));

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_MAC_FORWARDING_TABLE_OBJ, cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(ERR, "Could not translate %d to key %s,", (int)(BASE_MAC_TABLE_OBJ),
                    cps_api_key_print(&f.key, buff, sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    NAS_MAC_LOG(DEBUG, "Registering for BASE_MAC_VNI_TABLE_OBJ %s",
                cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = handle;
    f._write_function = cps_nas_mac_set_function;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }



    memset(&f,0,sizeof(f));

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_MAC_QUERY_OBJ, cps_api_qualifier_TARGET)) {
          NAS_MAC_LOG(ERR, "Could not translate %d to key %s,", (int)(BASE_MAC_QUERY_OBJ),
                  cps_api_key_print(&f.key, buff, sizeof(buff)-1));
          return STD_ERR(MAC,FAIL,0);
    }

    f.handle = handle;
    f._read_function = cps_nas_mac_get_function;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_MAC_FLUSH_OBJ,
                                             cps_api_qualifier_TARGET)) {
        NAS_MAC_LOG(DEBUG, "Could not translate %d to key %s",
                     (int)(BASE_MAC_FLUSH_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(MAC,FAIL,0);
    }

    f.handle = handle;
    f._write_function = nas_mac_flush_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_MAC_FLUSH_MANAGEMENT_OBJ,
                                                cps_api_qualifier_TARGET)) {
       NAS_MAC_LOG(DEBUG, "Could not translate %d to key %s",
                   (int)(BASE_MAC_FLUSH_MANAGEMENT_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
       return STD_ERR(MAC,FAIL,0);
    }

    f.handle = handle;
    f._write_function = nas_mac_flush_mgmt_set;
    f._read_function = nas_mac_flush_mgmt_get;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}

static bool nas_mac_update_port_to_vlan_mapping_(cps_api_object_t obj, cps_api_operation_types_t op)
{
     if(op == cps_api_oper_SET){
         NAS_MAC_LOG(ERR,"Set op not supported");
        return false;
    }

    cps_api_object_it_t it;
    hal_ifindex_t port_vlan_index = 0;
    hal_ifindex_t port_index = 0;
    cps_api_object_attr_t if_index_attr = cps_api_get_key_data(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if(if_index_attr !=  NULL){
        port_vlan_index = (uint32_t)cps_api_object_attr_data_u32(if_index_attr);
    }else{
        NAS_MAC_LOG(ERR,"missing ifindex for set");
        return false;
    }

    bool add_ports = false;
    if(op == cps_api_oper_CREATE){
        add_ports = true;
    }

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);
    cps_api_object_it_begin(obj,&it);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {


      switch ((int) cps_api_object_attr_id(it.attr)) {

      case DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS:
      case DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS:

          port_index = (hal_ifindex_t) cps_api_object_attr_data_u32(it.attr);
          if(add_ports){
              if(mac_port_to_vlan_id_map->find(port_index)== mac_port_to_vlan_id_map->end()){
                  std::unordered_set<hal_ifindex_t> vlan_list;
                  vlan_list.insert(port_vlan_index);
                  mac_port_to_vlan_id_map->insert({port_index,std::move(vlan_list)});
              }else{
                  mac_port_to_vlan_id_map->at(port_index).insert(port_vlan_index);
              }
          }else{
              if(mac_port_to_vlan_id_map->find(port_index)!= mac_port_to_vlan_id_map->end()){
                  mac_port_to_vlan_id_map->at(port_index).erase(port_vlan_index);
              }
          }
          break;

      default:
          break;

      }

    }
    return true;
}

static bool  nas_mac_untagged_vlan_1d_bridge(cps_api_object_t obj, void *param){

    NAS_MAC_LOG(DEBUG, "NAS mac untagged vlan id update for 1d bridges members");

    cps_api_object_attr_t _vn_untagged_vlan_attr = cps_api_object_attr_get(obj,
                                     DELL_IF_IF_INTERFACES_VLAN_GLOBALS_VN_UNTAGGED_VLAN);

    if (_vn_untagged_vlan_attr == NULL) {
        NAS_MAC_LOG(DEBUG, "Missing Vlan ID for untagged 1d bridge member");
        return true;

    }
    hal_vlan_id_t vlan_id = cps_api_object_attr_data_uint(_vn_untagged_vlan_attr);

    NAS_MAC_LOG(DEBUG, "Changed the default vn untagged vlan to %d", vlan_id);

    if (!vlan_id) {
        NAS_MAC_LOG(DEBUG, "Invalid Untagged Vlan id 0x%x, returning", vlan_id);
        return true;
    }
    std_mutex_simple_lock_guard lock(&untagged_vlan_id_mutex);
    bridge_1d_default_untag_vid = vlan_id;
    return true;
}


static cps_api_return_code_t nas_mac_vlan_process_port_membership(cps_api_object_t obj, bool add_ports)
{
    cps_api_object_it_t it;

    hal_vlan_id_t vlan_id = 0;
    hal_ifindex_t port_index = 0;

    if (add_ports) {
        NAS_MAC_LOG(DEBUG, "NAS Vlan port update for add, nothing to do, returning");
        return cps_api_ret_code_OK;
    }

    NAS_MAC_LOG(DEBUG, "NAS port vlan membership update");

    cps_api_object_attr_t vlan_id_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);

    if(vlan_id_attr == NULL) {
       NAS_MAC_LOG(DEBUG, "Missing Vlan ID for CPS Set");
       return cps_api_ret_code_ERR;
    }

    vlan_id = (hal_vlan_id_t) cps_api_object_attr_data_u16(vlan_id_attr);

    NAS_MAC_LOG(DEBUG, "Vlan index 0x%x", vlan_id);
    if (!vlan_id) {
        NAS_MAC_LOG(DEBUG, "Invalid Vlan index 0x%x, returning", vlan_id);
        return cps_api_ret_code_ERR;
    }

    cps_api_object_it_begin(obj,&it);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

          switch ((int) cps_api_object_attr_id(it.attr)) {

              case DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS:
              case DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS:

                  port_index = (hal_ifindex_t) cps_api_object_attr_data_u32(it.attr);
                  if (nas_mac_flush_vlan_entries_of_port(vlan_id, port_index) != STD_ERR_OK) {
                      return cps_api_ret_code_ERR;
                  }
                  break;
              default:
                  break;
        }
    }
    return cps_api_ret_code_OK;
}

static bool nas_mac_vlan_event_cb(cps_api_object_t obj, void *param)
{
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if(!nas_mac_update_port_to_vlan_mapping_(obj,op)){
        NAS_MAC_LOG(DEBUG,"Failed to process vlan port update");
    }
    NAS_MAC_LOG(DEBUG, "Received VLAN Port notification");

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    bool add_ports = false;

    if (op == cps_api_oper_CREATE) {
        NAS_MAC_LOG(DEBUG, "Received ADD VLAN operation code.. ");
        add_ports = true;
    } else if (op == cps_api_oper_DELETE) {
        NAS_MAC_LOG(DEBUG, "Received DEL VLAN operation code.. ");
    } else {
        NAS_MAC_LOG(DEBUG, "Received Invalid VLAN operation code, 0x%x", op);
        return false;
    }


    if(nas_mac_vlan_process_port_membership(obj, add_ports) != cps_api_ret_code_OK){
        return true;
    }

    NAS_MAC_LOG(DEBUG, "Port vlan membership event processing done .. ");
    return true;
}

static bool nas_mac_fdb_event_cb(cps_api_object_t obj, void *param)
{

    nas_mac_entry_t entry;
    nas::attr_set_t attrs;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    if(op != cps_api_oper_CREATE and op != cps_api_oper_DELETE){
        return true;
    }

    NAS_MAC_LOG(INFO,"FDB event cb operation type %d",op);

    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
        case BASE_ROUTE_OBJ_NBR_AF:
            /*
             * Only process AF_BRIDGE family message
             */

            if(cps_api_object_attr_data_uint(it.attr) != AF_BRIDGE){
                return true;
            }
            break;

        case BASE_ROUTE_OBJ_NBR_ADDRESS:
        {
            size_t len = cps_api_object_attr_len(it.attr);
            entry.endpoint_ip.af_index = (len == HAL_INET4_LEN) ? HAL_INET4_FAMILY : HAL_INET6_FAMILY;
            memcpy(&entry.endpoint_ip.u,cps_api_object_attr_data_bin(it.attr),
                    sizeof(entry.endpoint_ip.u));
            attrs.add(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP);
            attrs.add(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY);
        }
            break;

        case BASE_ROUTE_OBJ_NBR_MAC_ADDR:
            std_string_to_mac(&entry.entry_key.mac_addr, (char*)cps_api_object_attr_data_bin(it.attr),
                               cps_api_object_attr_len(it.attr));
            attrs.add(BASE_MAC_TABLE_MAC_ADDRESS);
            break;

        case BASE_ROUTE_OBJ_NBR_IFINDEX:
            entry.ifindex = cps_api_object_attr_data_uint(it.attr);
            attrs.add(BASE_MAC_TABLE_IFINDEX);
            break;
        }
    }
    entry.cache = true;
    if(attrs.contains(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP)){
        return nas_mac_process_os_event(entry,attrs,op);
    }

    return true;

}



static bool nas_mac_if_vlan_state_event_cb(cps_api_object_t obj, void * param){
    cps_api_object_attr_t vlan_attr = cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
    cps_api_object_attr_t bridge_attr = cps_api_object_attr_get(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_t parent_bridge = cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_PARENT_BRIDGE);

    if (vlan_attr == NULL || bridge_attr == NULL) {
        NAS_MAC_LOG(ERR,"No VLAN ID/bridge attr passed to process VLAN updates");
        return false;
    }
    hal_ifindex_t bridge_ifindex = (hal_ifindex_t)cps_api_object_attr_data_u32(bridge_attr);
    hal_vlan_id_t vlan_id = (hal_vlan_id_t)cps_api_object_attr_data_u16(vlan_attr);
    cps_api_operation_types_t op = cps_api_object_type_operation (cps_api_object_key (obj));

    std_mutex_simple_lock_guard lock(&nas_mac_mutex);
    if (op == cps_api_oper_CREATE) {
        mac_vlan_id_to_ifindex_map->insert({vlan_id, bridge_ifindex});
    }

    if (op == cps_api_oper_DELETE) {
        mac_vlan_id_to_ifindex_map->erase(vlan_id);
        for(auto it = mac_port_to_vlan_id_map->begin(); it != mac_port_to_vlan_id_map->end(); ++it){
            it->second.erase(bridge_ifindex);
        }
        return true;
    }
    std_mutex_simple_lock_guard lock_id(&untagged_vlan_id_mutex);
    if (parent_bridge != NULL) {
        /*  parent bridge attached processing during vlan interface create or set operation
         *  Store parent bridge to vlan id mapping if parent bridge is non-empty string
         *  if parent bridge is empty string then remove the mapping. */
       size_t len = cps_api_object_attr_len(parent_bridge);
       if (len != 0) {
           const char *parent_name = (const char *)cps_api_object_attr_data_bin(parent_bridge);
           interface_ctrl_t i;
           memset(&i,0,sizeof(i));
           safestrncpy(i.if_name,parent_name,sizeof(i.if_name));
           i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
           if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
               EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                          "Can't get parent interface control information for parent %s",parent_name);
               return STD_ERR(MAC,FAIL,0);
           }
           EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
               "Attach vlan parent's ifindex %d and vlan id %d", i.if_index ,vlan_id);
           map_parent_br_to_vlan_id->insert({i.if_index ,vlan_id});

       } else {
           /* Its a detach  based on vlan-id remove the entry */
           for(auto entry = map_parent_br_to_vlan_id->begin(); entry != map_parent_br_to_vlan_id->end(); ++entry){
              if (entry->second == vlan_id) {
                 EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                    "Detach vlan parent ifindex %d and vlan id %d", entry->first , entry->second);
                 map_parent_br_to_vlan_id->erase(entry);
                 break;
              }
           }
       }
    }


    return true;
}

/*  Remote endpoint create /delete event handler  */
static bool nas_mac_endpoint_ev_cb(cps_api_object_t obj, void *param)
{

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    bool add = (op == cps_api_oper_DELETE)? false : true;

    ndi_obj_id_t tunnel_obj_id = 0;
    hal_ip_addr_t ip_addr;
    memset(&ip_addr,0,sizeof(ip_addr));

    cps_api_object_attr_t vtep_attr = cps_api_get_key_data(obj,IF_INTERFACES_INTERFACE_NAME);
    cps_api_object_attr_t tunnel_id_attr = cps_api_object_attr_get(obj,DELL_IF_IF_INTERFACES_INTERFACE_REMOTE_ENDPOINT_TUNNEL_ID);
    if(!vtep_attr) {
        return true;
    }
    if ((add)  && (!tunnel_id_attr)) {
        return true;
    }
    const char * vtep_name = (const char *)cps_api_object_attr_data_bin(vtep_attr);

    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
        case DELL_IF_IF_INTERFACES_INTERFACE_REMOTE_ENDPOINT_TUNNEL_ID:
            tunnel_obj_id = cps_api_object_attr_data_u64(it.attr);
            break;

        case DELL_IF_IF_INTERFACES_INTERFACE_REMOTE_ENDPOINT_ADDR_FAMILY :
            ip_addr.af_index = cps_api_object_attr_data_uint(it.attr);
            break;

        case DELL_IF_IF_INTERFACES_INTERFACE_REMOTE_ENDPOINT_ADDR:
            memcpy(&ip_addr.u,cps_api_object_attr_data_bin(it.attr),
                    cps_api_object_attr_len(it.attr));
            break;
        }
    }

    if (tunnel_obj_id == 0) {
        /* If tunnel ID is 0 then consider it deletion of tunnel ID case  */
        add = false;
    }

    NAS_MAC_LOG(DEBUG, "Remote endpoint %s event on the vtep intf %s ", (add) ? "create" : "delete", vtep_name);
    return _process_remote_endpint(vtep_name,ip_addr,tunnel_obj_id,add);

}

static bool nas_mac_bridge_ev_cb(cps_api_object_t obj, void *param)
{

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    if(op != cps_api_oper_CREATE and op != cps_api_oper_DELETE){
        return true;
    }

    cps_api_object_attr_t br_attr = cps_api_get_key_data(obj,BRIDGE_DOMAIN_BRIDGE_NAME);
    if(!br_attr){
        return true;
    }

    const char * bridge_name = (const char *)cps_api_object_attr_data_bin(br_attr);
    const char * vtep_name = nullptr;
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
        case BRIDGE_DOMAIN_BRIDGE_MEMBER_INTERFACE:
            vtep_name = (const char *)cps_api_object_attr_data_bin(it.attr);
            break;
        }

    }

    if(!vtep_name or !bridge_name) return true;

    return _process_bridge_event(bridge_name,vtep_name, op == cps_api_oper_CREATE ? true: false);

}

static bool nas_mac_if_event_cb(cps_api_object_t obj, void *param)
{
    NAS_MAC_LOG(DEBUG,"Interface event handling");

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG, "NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,IF_INTERFACES_STATE_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        NAS_MAC_LOG(ERR,"Interface Index is missing in the interface object event");
        return true;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t oper_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_OPER_STATUS);

    if(oper_attr == NULL){
        /*  Do not care  and return if oper state not present*/
        return true;
    }

    IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t oper_status = (IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t)
                                               cps_api_object_attr_data_u32(oper_attr);

    if(oper_status == IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_DOWN){
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on interface %d failed when it went oper down",index);
            return true;
        }
    }
    NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on an interface %d",index);

    return true;
}


t_std_error nas_mac_reg_if_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    cps_api_key_from_attr_with_qual(&key, DELL_BASE_IF_CMN_IF_INTERFACES_STATE_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_if_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for if events");
        return STD_ERR(MAC,FAIL,0);
    }
    return STD_ERR_OK;
}


static bool nas_mac_lag_event_cb(cps_api_object_t obj, void *param)
{

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        return false;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS);

    if(admin_attr == NULL){
        return false;
    }

    IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_t admin_status = (IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_t)
                                                                    cps_api_object_attr_data_u32(admin_attr);

    if(admin_status == IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_DOWN){
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on LAG interface %d failed when it went oper down",index);
            return false;
        }
        NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on LAG interface %d",index);
    }

    return true;
}


static bool nas_mac_lag_state_event_cb(cps_api_object_t obj, void *param)
{

    if(!mac_auto_flush){
        NAS_MAC_LOG(DEBUG,"NAS MAC auto flush management disabled,nothing to do");
        return true;
    }

    cps_api_object_attr_t ifix_attr = cps_api_get_key_data(obj,IF_INTERFACES_STATE_INTERFACE_IF_INDEX);

    if (ifix_attr == NULL) {
        return false;
    }

    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t oper_attr = cps_api_object_attr_get(obj,IF_INTERFACES_STATE_INTERFACE_OPER_STATUS);

    if(oper_attr == NULL){
        return false;
    }
    IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t oper_status = (IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t)
                                                                    cps_api_object_attr_data_u32(oper_attr);

    if(oper_status == IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_DOWN){
        if(nas_mac_handle_if_down(index) != STD_ERR_OK){
            NAS_MAC_LOG(ERR,"Flush on LAG interface %d failed when it went oper down",index);
            return false;
        }
        NAS_MAC_LOG(DEBUG,"Flushed Dynamic Entries on LAG interface %d",index);
    }

    return true;
}


t_std_error nas_mac_reg_lag_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    cps_api_key_from_attr_with_qual(&key, BASE_IF_LAG_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_lag_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for lag events");
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&reg,0,sizeof(reg));
    cps_api_key_t lag_state_key;

    cps_api_key_from_attr_with_qual(&lag_state_key, BASE_IF_LAG_IF_INTERFACES_STATE_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &lag_state_key;

    if (cps_api_event_thread_reg(&reg, nas_mac_lag_state_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for lag events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_reg_vlan_event (void) {
    cps_api_event_reg_t reg;
    cps_api_key_t key;

    memset(&reg,0,sizeof(reg));

    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not initialize the event service");
        return STD_ERR(MAC,FAIL,0);
    }

    if (cps_api_event_thread_init() != cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not initialize the event thread");
        return STD_ERR(MAC,FAIL,0);
    }

    cps_api_key_from_attr_with_qual(&key, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_vlan_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for vlan events");
        return STD_ERR(MAC,FAIL,0);
    }

    cps_api_key_from_attr_with_qual(&key, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_vlan_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for vlan events");
        return STD_ERR(MAC,FAIL,0);
    }

    memset(&reg,0,sizeof(reg));
    cps_api_key_from_attr_with_qual(&key, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_OBJ,
                                        cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

     if (cps_api_event_thread_reg(&reg, nas_mac_if_vlan_state_event_cb,NULL)!=cps_api_ret_code_OK) {
         NAS_MAC_LOG(ERR, "Could not register for vlan events");
         return STD_ERR(MAC,FAIL,0);
    }

    cps_api_key_from_attr_with_qual(&key, DELL_BASE_IF_CMN_IF_INTERFACES_OBJ,
                                    cps_api_qualifier_OBSERVED);

    reg.number_of_objects = 1;
    reg.objects = &key;

    if (cps_api_event_thread_reg(&reg, nas_mac_untagged_vlan_1d_bridge,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for vlan events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_reg_fdb_event (void) {

    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    reg.number_of_objects = 1;
    reg.objects = &key;
    cps_api_key_from_attr_with_qual(&key, OS_RE_BASE_ROUTE_OBJ_NBR_OBJ,
                                       cps_api_qualifier_OBSERVED);
    if (cps_api_event_thread_reg(&reg, nas_mac_fdb_event_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for fdb events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;
}

/*  Event handler for Remote end point Tunnel creation/deletion
 *  Tunnel ID is requried for configuring MAC learnt on the remtoe endpoint IP address. */
static t_std_error nas_mac_reg_endpoint_event(void){
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    reg.number_of_objects = 1;
    reg.objects = &key;
    cps_api_key_from_attr_with_qual(&key, DELL_IF_IF_INTERFACES_INTERFACE_REMOTE_ENDPOINT,
                                       cps_api_qualifier_OBSERVED);
    if (cps_api_event_thread_reg(&reg, nas_mac_endpoint_ev_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for fdb events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;

}
/*  Bridge Domain event handler is for 1D bridge creation/deletion. Creates mapping between bridge name to bridge ID
 *  used to programmed NPU  */
static t_std_error nas_mac_reg_bridge_event(void){
    cps_api_event_reg_t reg;
    cps_api_key_t key;
    memset(&reg,0,sizeof(reg));

    reg.number_of_objects = 1;
    reg.objects = &key;
    cps_api_key_from_attr_with_qual(&key, BRIDGE_DOMAIN_BRIDGE_OBJ,
                                       cps_api_qualifier_OBSERVED);
    if (cps_api_event_thread_reg(&reg, nas_mac_bridge_ev_cb,NULL)!=cps_api_ret_code_OK) {
        NAS_MAC_LOG(ERR, "Could not register for fdb events");
        return STD_ERR(MAC,FAIL,0);
    }

    return STD_ERR_OK;

}


t_std_error nas_mac_init(cps_api_operation_handle_t handle) {

    t_std_error rc;
    e_std_soket_type_t domain = e_std_sock_UNIX;
    if (( rc = std_sock_create_pair(domain, true, npu_thread_fd)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-MAC-INIT","Failed to create socketpair for mac npu thread");
        return STD_ERR(NPU,FAIL,0);
    }

    if (( rc = std_sock_create_pair(domain, true, cps_thread_fd)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-MAC-INIT","Failed to create socketpair for mac npu thread");
        return STD_ERR(NPU,FAIL,0);
    }
    std_thread_create_param_t nas_l2_npu_thread;
    std_thread_init_struct(&nas_l2_npu_thread);
    nas_l2_npu_thread.name = "nas-l2-npu-thrd";
    nas_l2_npu_thread.thread_function = (std_thread_function_t)nas_l2_mac_npu_req_handler;

    if (std_thread_create(&nas_l2_npu_thread)!=STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Error creating nas mac npu thread");
        return STD_ERR(MAC,FAIL,0);
    }

    std_thread_create_param_t nas_l2_cps_thread;
    std_thread_init_struct(&nas_l2_cps_thread);
    nas_l2_cps_thread.name = "nas-l2-cps-thrd";
    nas_l2_cps_thread.thread_function = (std_thread_function_t)nas_l2_mac_cps_req_handler;

    if (std_thread_create(&nas_l2_cps_thread)!=STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Error creating nas mac cps thread");
        return STD_ERR(MAC,FAIL,0);
    }


    cps_api_event_reg_t reg;
    memset(&reg,0,sizeof(reg));

    if ((rc = cps_nas_mac_init(handle)) != STD_ERR_OK){
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = ndi_mac_event_notify_register(nas_mac_event_notification_cb))!= STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = ndi_switch_mac_age_time_set(0, SWITCH_DEFAULT_MAC_AGE_TIMEOUT))!= STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_vlan_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_fdb_event()) != STD_ERR_OK) {
            return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_if_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if ((rc = nas_mac_reg_lag_event()) != STD_ERR_OK) {
        return STD_ERR(MAC,FAIL,0);
    }

    if((rc = nas_mac_event_handle_init() != STD_ERR_OK)){
        return rc;
    }

    if((rc = nas_mac_reg_bridge_event() != STD_ERR_OK)){
        return rc;
    }

    if((rc = nas_mac_reg_endpoint_event())!= STD_ERR_OK){
        return rc;
    }

    return rc;
}
