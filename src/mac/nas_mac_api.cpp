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
#include "cps_class_map.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mac.h"
#include "nas_base_utils.h"
#include "nas_linux_l2.h"
#include "nas_if_utils.h"
#include "dell-base-interface-common.h"
#include "ds_common_types.h"
#include "std_ip_utils.h"
#include "std_utils.h"

#include <string>
#include <map>
#include <set>
#include <stdlib.h>
#include <mutex>

typedef std::list<nas_mac_entry_t>nas_mac_list;
typedef std::unordered_set<std::string>nas_mac_str_list;


static std::recursive_mutex _vxlan_mtx;
static std::mutex _bridge_mtx;

struct vni_rem_ip_hash{
    std::size_t operator()(const vni_rem_ip_t & k) const{

        return ((std::hash<std::string>{}(k.ip)
                 ^ (std::hash<int>{}(k.br_index) << 1)) >> 1);
    }

};

static auto vxlan_pending_macs = * new std::unordered_map<vni_rem_ip_t, nas_mac_list,vni_rem_ip_hash> ;
static auto vxlan_remote_macs = * new std::unordered_map<vni_rem_ip_t, nas_mac_str_list,vni_rem_ip_hash> ;
static auto known_rem_ips = * new std::unordered_set<vni_rem_ip_t,vni_rem_ip_hash> ;
static auto bridge_map = * new std::unordered_map<hal_ifindex_t, hal_ifindex_t> ;
static auto remote_ip_event_mask = * new std::unordered_set<vni_rem_ip_t,vni_rem_ip_hash> ;
static auto vxlan_bridge_map = * new std::unordered_map<hal_ifindex_t, hal_ifindex_t>;
static auto tunnel_endpoint_map = * new std::unordered_map<vni_rem_ip_t,ndi_obj_id_t,vni_rem_ip_hash>;
static auto tunnel_id_to_vtep_map = * new std::unordered_map<ndi_obj_id_t,std::string>;
static const size_t mac_addr_str_len = 20;

struct _remote_pending_entry {
    nas_mac_entry_t entry;
    nas::attr_set_t attrs;
    cps_api_operation_types_t op;
};
using _remote_entry_list = std::list<_remote_pending_entry>;

static auto _remote_pending_entry_map = * new std::unordered_map<hal_ifindex_t, _remote_entry_list>;

static bool nas_mac_entry_action_supported(BASE_MAC_PACKET_ACTION_t action)
{
    return (action == BASE_MAC_PACKET_ACTION_FORWARD ||
            action == BASE_MAC_PACKET_ACTION_LOG ||
            action == BASE_MAC_PACKET_ACTION_TRAP ||
            action == BASE_MAC_PACKET_ACTION_DROP);
}

static std::unordered_map <cps_api_operation_types_t, const char *> _oper_type = {
    {cps_api_oper_CREATE, "CREATE"},
    {cps_api_oper_SET, "UPDATE"},
    {cps_api_oper_DELETE, "DELETE"},
};
static bool nas_mac_get_bridge_from_vtep(hal_ifindex_t & vtep_index, hal_ifindex_t & br_index){
    std::lock_guard<std::mutex> _lk(_bridge_mtx);
    auto it = vxlan_bridge_map.find(vtep_index);
    if(it != vxlan_bridge_map.end()){
        br_index = it->second;
        return true;
    }

    return false;
}

bool nas_mac_get_vtep_name_from_tunnel_id(ndi_obj_id_t id, std::string & s){
    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    auto it = tunnel_id_to_vtep_map.find(id);
    if(it == tunnel_id_to_vtep_map.end()){
        return false;
    }

    s = it->second;
    return true;
}

static bool nas_mac_validate_params(nas::attr_set_t & attrs, cps_api_operation_types_t op){

    if(op == cps_api_oper_DELETE){
        return true;
    }
    if (!attrs.contains(BASE_MAC_TABLE_MAC_ADDRESS)){
        return false;
    }

    if( op == cps_api_oper_CREATE){

        if (attrs.contains(BASE_MAC_FORWARDING_TABLE_BR_NAME) && attrs.contains(BASE_MAC_TABLE_IFINDEX)){
            if((attrs.contains(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP) &&
               attrs.contains(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY)) ||
                (attrs.contains(BASE_MAC_TABLE_VLAN) ))
                return true;
        }else if(attrs.contains(BASE_MAC_TABLE_VLAN) &&
                attrs.contains(BASE_MAC_TABLE_IFINDEX)){
            return true;
        }
    } else if (op == cps_api_oper_SET) {
        if (attrs.contains(BASE_MAC_TABLE_VLAN) || attrs.contains(BASE_MAC_FORWARDING_TABLE_BR_NAME)) {
            return true;
        }
    }

    return false;
}

static void nas_mac_get_str_from_mac(hal_mac_addr_t & mac_addr, std::string & s){

    char mac_addr_str[mac_addr_str_len];
    memset(mac_addr_str,0,sizeof(mac_addr_str));
    std_mac_to_string(&mac_addr,mac_addr_str,mac_addr_str_len);
    s = std::string(mac_addr_str);
}


void nas_mac_log_entry(nas_mac_entry_t *entry) {

    const char *mac = (const char *)&(entry->entry_key.mac_addr[0]);
    if ( entry->entry_type == NDI_MAC_ENTRY_TYPE_1D_LOCAL) {
        EV_LOGGING(L2MAC, INFO,"NAS-MAC",
          " Entry Type: 1D, Bridge Index: %d, Vlan Id: %d, Interface Index: %d,"
         " MAC Address %02x:%02x:%02x:%02x:%02x:%02x",
                        entry->bridge_ifindex, entry->entry_key.vlan_id, entry->ifindex,
                        mac[0],mac[1],mac[2], mac[3],mac[4],mac[5]);
    } else if ( entry->entry_type == NDI_MAC_ENTRY_TYPE_1D_REMOTE) {
        EV_LOGGING(L2MAC, INFO,"NAS-MAC"," Entry Type: 1D Remote , Bridge Index: %d, Vlan Id: %d, Remote IP: %d "
                                " MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                        entry->bridge_ifindex, entry->entry_key.vlan_id, entry->ifindex,
                        mac[0],mac[1],mac[2], mac[3],mac[4],mac[5]);
    } else if ( entry->entry_type == NDI_MAC_ENTRY_TYPE_1Q){
        EV_LOGGING(L2MAC, INFO,"NAS-MAC"," Entry Type: 1Q, Vlan Id: %d, Interface Index: %d, "
               " MAC Address %02x:%02x:%02x:%02x:%02x:%02x",
                        entry->entry_key.vlan_id, entry->ifindex,
                        mac[0],mac[1],mac[2], mac[3],mac[4],mac[5]);
    }

}
static t_std_error nas_mac_obj_to_entry (cps_api_object_t obj, nas_mac_entry_t *entry) {

    cps_api_object_it_t it;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    entry->npu_configured = true;
    entry->os_configured =false;
    entry->is_static = false;
    entry->pkt_action = BASE_MAC_PACKET_ACTION_FORWARD;
    entry->entry_type = NDI_MAC_ENTRY_TYPE_1Q;
    entry->cache = false;
    nas::attr_set_t attrs;

    cps_api_object_attr_t _1d_attr;
    _1d_attr = cps_api_object_attr_get(obj, BASE_MAC_FORWARDING_TABLE_MAC_ADDRESS);
    if(_1d_attr){
        entry->entry_type = NDI_MAC_ENTRY_TYPE_1D_LOCAL;
    }


    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch ((int) cps_api_object_attr_id(it.attr)) {

            case BASE_MAC_TABLE_VLAN:
            case BASE_MAC_FORWARDING_TABLE_VLAN:
                entry->entry_key.vlan_id = cps_api_object_attr_data_u16(it.attr);
                attrs.add(BASE_MAC_TABLE_VLAN);
                break;

            case BASE_MAC_TABLE_IFINDEX:
            case BASE_MAC_FORWARDING_TABLE_IFINDEX:
                entry->ifindex = cps_api_object_attr_data_u32(it.attr);
                attrs.add(BASE_MAC_TABLE_IFINDEX);
                break;

            case BASE_MAC_TABLE_IFNAME:
            case BASE_MAC_FORWARDING_TABLE_IFNAME:
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
                attrs.add(BASE_MAC_TABLE_IFINDEX);
                break;
            }
            case BASE_MAC_TABLE_MAC_ADDRESS:
            case BASE_MAC_FORWARDING_TABLE_MAC_ADDRESS:
            {
                size_t mac_len = cps_api_object_attr_len(it.attr);
                if (mac_len < sizeof(hal_mac_addr_t)) {
                    NAS_MAC_LOG(ERR, "Invalid mac address format");
                    return STD_ERR(MAC,CFG,0);
                }
                memcpy(entry->entry_key.mac_addr, cps_api_object_attr_data_bin(it.attr),
                        sizeof(hal_mac_addr_t));
               attrs.add(BASE_MAC_TABLE_MAC_ADDRESS);
                break;
            }

            case BASE_MAC_TABLE_ACTIONS:
            case BASE_MAC_FORWARDING_TABLE_ACTIONS:
            {
                BASE_MAC_PACKET_ACTION_t pkt_action = (BASE_MAC_PACKET_ACTION_t)
                                                    cps_api_object_attr_data_u32(it.attr);
                if (!nas_mac_entry_action_supported(pkt_action)) {
                    NAS_MAC_LOG(ERR,  "Unsupported action type: %d", entry->pkt_action);
                    return STD_ERR(MAC,CFG,0);
                }
                entry->pkt_action = pkt_action;

                break;
            }
            case BASE_MAC_TABLE_STATIC:
            case BASE_MAC_FORWARDING_TABLE_STATIC:
                entry->is_static = cps_api_object_attr_data_u32(it.attr);
                if(entry->is_static){
                    entry->cache = true;
                }
                break;

            case BASE_MAC_TABLE_CONFIGURE_OS:
            case BASE_MAC_FORWARDING_TABLE_CONFIGURE_OS:
                entry->os_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            case BASE_MAC_TABLE_CONFIGURE_NPU:
            case BASE_MAC_FORWARDING_TABLE_CONFIGURE_NPU:

                entry->npu_configured = cps_api_object_attr_data_u32(it.attr);
                break;

            case BASE_MAC_FORWARDING_TABLE_BR_NAME:
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

                if(i.int_type == nas_int_type_DOT1D_BRIDGE){
                    entry->bridge_ifindex = i.if_index;
                    entry->bridge_id = i.bridge_id;
                    attrs.add(BASE_MAC_FORWARDING_TABLE_BR_NAME);
                }else{
                    NAS_MAC_LOG(ERR,"Failed to find bridge %s information",name);
                }
            }
                break;

            case BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY:
                entry->endpoint_ip.af_index = cps_api_object_attr_data_u32(it.attr);
                attrs.add(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY);
                entry->entry_type = NDI_MAC_ENTRY_TYPE_1D_REMOTE;
                break;

            case BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR:
                {

                cps_api_object_attr_t af_attr;
                af_attr = cps_api_object_attr_get(obj, BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY);
                if(!af_attr){
                    NAS_MAC_LOG(ERR,"Can't have IP address without Address Class");
                    return false;
                }
                entry->endpoint_ip.af_index = cps_api_object_attr_data_u32(af_attr);
                attrs.add(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP_ADDR_FAMILY);

                }

                if(entry->endpoint_ip.af_index == AF_INET){
                    memcpy(&entry->endpoint_ip.u.ipv4,cps_api_object_attr_data_bin(it.attr),
                            sizeof(entry->endpoint_ip.u.ipv4));
                }else{
                    memcpy(&entry->endpoint_ip.u.ipv6,cps_api_object_attr_data_bin(it.attr),
                                            sizeof(entry->endpoint_ip.u.ipv6));
                }
                attrs.add(BASE_MAC_FORWARDING_TABLE_ENDPOINT_IP);
                break;

            case BASE_MAC_TABLE_PUBLISH:
            case BASE_MAC_FORWARDING_TABLE_PUBLISH:
                if(cps_api_object_attr_data_uint(it.attr)){
                    entry->publish=true;
                }
                break;

            default:
                break;
        }
    }

    if(!nas_mac_validate_params(attrs,op)){
        NAS_MAC_LOG(ERR,"Failed to validate mac request");
        return STD_ERR(MAC,FAIL,0);
    }

    /*  Log MAC entry  */

    const char *oper_type = NULL;
    auto _oper_it = _oper_type.find(op);
    if (_oper_it != _oper_type.end()) {
        oper_type = _oper_it->second;
        EV_LOGGING(L2MAC, INFO, "NAS-MAC", " CPS MAC Request: operation:  %s", oper_type);
    }
    nas_mac_log_entry(entry);
    return STD_ERR_OK;
}


t_std_error nas_mac_update_entry_in_os(nas_mac_entry_t *entry,
                                       cps_api_operation_types_t op){
     cps_api_object_guard og(cps_api_object_create());
     if(og.get() == nullptr) return STD_ERR(MAC,NOMEM,0);
     cps_api_object_set_type_operation(cps_api_object_key(og.get()),op);
     cps_api_object_attr_add_u32(og.get(),BASE_MAC_TABLE_IFINDEX,entry->ifindex);
     cps_api_object_attr_add_u32(og.get(),BASE_MAC_TABLE_STATIC,entry->is_static);
     cps_api_object_attr_add_u16(og.get(),BASE_MAC_TABLE_VLAN,entry->entry_key.vlan_id);
     cps_api_object_attr_add(og.get(),BASE_MAC_TABLE_MAC_ADDRESS,(void *)&entry->entry_key.mac_addr,
                                 sizeof(entry->entry_key.mac_addr));

     interface_ctrl_t intf_ctrl;
     memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

     intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
     intf_ctrl.if_index = entry->ifindex;

     if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
         cps_api_object_attr_add(og.get(),BASE_MAC_TABLE_IFNAME,(void *)intf_ctrl.if_name,
                                     strlen(intf_ctrl.if_name)+1);
     }
     t_std_error rc = nas_os_mac_update_entry(og.get());
     return rc;
}

bool _get_endpoint_tunnel_id(vni_rem_ip_t & _rem_ip, ndi_obj_id_t & obj_id){
    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    auto it = tunnel_endpoint_map.find(_rem_ip);
    if(it == tunnel_endpoint_map.end()){
        NAS_MAC_LOG(ERR,"failed to find tunnel port id for bridge %d",
                _rem_ip.br_index);
        return false;
    }
    obj_id = it->second;
    return true;
}

static bool nas_mac_fill_ndi_entry(ndi_mac_entry_t & ndi_mac_entry,nas_mac_entry_t & entry ){

    if(entry.ifindex != 0){
        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = entry.ifindex;

        if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
            EV_LOGGING(L2MAC,ERR,"NAS-MAC", "Get interface info failed for ifindex %d.",entry.ifindex);
            return false;
        }

        ndi_obj_id_t obj_id;
        if (intf_ctrl.int_type == nas_int_type_LAG) {
            if (nas_get_lag_id_from_if_index(entry.ifindex, &obj_id) == STD_ERR_OK) {
                ndi_mac_entry.ndi_lag_id = obj_id;
            }
        }
        ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
        ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
    }

    ndi_mac_entry.npu_id = 0;
    ndi_mac_entry.vlan_id = entry.entry_key.vlan_id;
    ndi_mac_entry.mac_entry_type = entry.entry_type;

    EV_LOGGING(L2MAC,DEBUG,"NAS-MAC", "nas_mac_fill_ndi_entry ifx %llu vlan_id %d type %d ",
                                                       entry.ifindex, ndi_mac_entry.vlan_id, ndi_mac_entry.mac_entry_type );
    if(entry.entry_type != NDI_MAC_ENTRY_TYPE_1Q){
        ndi_mac_entry.bridge_id = entry.bridge_id;
        if(entry.entry_type == NDI_MAC_ENTRY_TYPE_1D_REMOTE){
            memcpy(&ndi_mac_entry.endpoint_ip,&entry.endpoint_ip,sizeof(ndi_mac_entry.endpoint_ip));
            vni_rem_ip_t _rem_ip = { entry.endpoint_ip,entry.bridge_ifindex };
            if(!_get_endpoint_tunnel_id(_rem_ip,ndi_mac_entry.endpoint_ip_port)){
                return false;
            }
        } else {
            /* Handle setting vlanid for untagged 1d bridge ports, could be attached ones or direct untagged ones */
            if (ndi_mac_entry.vlan_id == 0) {
                if (!nas_mac_get_1d_br_untag_vid(entry.bridge_ifindex, ndi_mac_entry.vlan_id)) {
                    EV_LOGGING(L2MAC,ERR,"NAS-MAC", "failed to get vlan_id for 1d bridge ifindex %d.",entry.bridge_ifindex);
                }


            }

        }
    }

    memcpy(ndi_mac_entry.mac_addr, entry.entry_key.mac_addr, sizeof(hal_mac_addr_t));
    ndi_mac_entry.is_static = entry.is_static;
    ndi_mac_entry.action = entry.pkt_action;
    return true;

}


static t_std_error nas_mac_create_entry_hw(nas_mac_entry_t *entry){

    ndi_mac_entry_t ndi_mac_entry;
    t_std_error rc;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));

    if(!nas_mac_fill_ndi_entry(ndi_mac_entry,*entry)){
        return STD_ERR(MAC,CFG,0);
    }

    if((rc = ndi_create_mac_entry(&ndi_mac_entry)) != STD_ERR_OK){
        return rc;
    }

    return STD_ERR_OK;
}


static void nas_mac_send_event_notification(nas_mac_entry_t & entry,nas_l2_mac_op_t op_type){
    unsigned int len = sizeof(nas_l2_event_header_t)+ sizeof(nas_mac_npu_event_t);
    void * data = calloc(len,sizeof(char));

    if(!data){
        NAS_MAC_LOG(ERR,"Failed to allocate memory for sending data to fd");
        return;
    }

    nas_mac_npu_event_t * mac_event = (nas_mac_npu_event_t *)((char *)data + sizeof(nas_l2_event_header_t));
    nas_l2_event_header_t *hdr = (nas_l2_event_header_t *)data;

    memcpy(&mac_event->entry,&entry,sizeof(entry));
    mac_event->op_type = op_type;

    hdr->ev_type = NAS_MAC_NPU_EVENT;
    hdr->len = 1;

    nas_mac_send_npu_event_notification(data,len);
    free(data);

}


static bool _check_if_flooding_mac(hal_mac_addr_t & mac_addr){

    hal_mac_addr_t _zero_mac = {0};
    if(memcmp(mac_addr,_zero_mac,sizeof(hal_mac_addr_t)) == 0){
        return true;
    }

    return false;
}

/*
 * Publish an event when a remote end point is being added/deleted
 */
static bool nas_mac_publish_remote_ip_event(nas_mac_entry_t & _mac_entry,vni_rem_ip_t & entry,
                                            cps_api_operation_types_t op){
    if(op == cps_api_oper_CREATE){
        if (remote_ip_event_mask.find(entry) != remote_ip_event_mask.end()){
            return true;
        }
        remote_ip_event_mask.insert(entry);
    }else if(op ==cps_api_oper_DELETE) {
        remote_ip_event_mask.erase(entry);
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == nullptr){
        NAS_MAC_LOG(ERR,"Failed to allocate memory for object publish");
        return false;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MAC_TUNNEL_ENDPOINT_EVENT_OBJ,
                                          cps_api_qualifier_OBSERVED);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_MAC_TUNNEL_ENDPOINT_EVENT_FLOODING_ENABLE,
            op == cps_api_oper_SET ? false :
            _check_if_flooding_mac(_mac_entry.entry_key.mac_addr) ? true : false);

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = _mac_entry.ifindex;

    if(dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
        cps_api_object_attr_add(obj,BASE_MAC_TUNNEL_ENDPOINT_EVENT_INTERFACE_NAME,(const void *)intf_ctrl.if_name,
                strlen(intf_ctrl.if_name)+1);
    }

    cps_api_object_attr_add_u32(obj,BASE_MAC_TUNNEL_ENDPOINT_EVENT_IP_ADDR_FAMILY,_mac_entry.endpoint_ip.af_index);

    if(_mac_entry.endpoint_ip.af_index == AF_INET){
        cps_api_object_attr_add(obj,BASE_MAC_TUNNEL_ENDPOINT_EVENT_IP_ADDR,(const void *)&_mac_entry.endpoint_ip.u.ipv4,
               sizeof(_mac_entry.endpoint_ip.u.ipv4));
    }else{
        cps_api_object_attr_add(obj,BASE_MAC_TUNNEL_ENDPOINT_EVENT_IP_ADDR,(const void *)&_mac_entry.endpoint_ip.u.ipv6,
                       sizeof(_mac_entry.endpoint_ip.u.ipv6));
    }

    cps_api_object_set_type_operation(cps_api_object_key(obj),op);
    if(nas_mac_event_publish(obj) != STD_ERR_OK ){
        return false;
    }

    return true;
}


bool nas_mac_update_remote_macs_cache(nas_mac_entry_t & entry,bool add){

    if(!entry.cache){
        return true;
    }
    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    std::string mac_addr;
    nas_mac_get_str_from_mac(entry.entry_key.mac_addr,mac_addr);
    vni_rem_ip_t rem_ip = { entry.endpoint_ip,entry.bridge_ifindex};
    auto it  = vxlan_remote_macs.find(rem_ip);
    if(add){
        if(it == vxlan_remote_macs.end()){
            nas_mac_str_list l = {mac_addr};
            vxlan_remote_macs[rem_ip] = l;
        }else{
            it->second.insert(mac_addr);
        }
    }else{
        if(it != vxlan_remote_macs.end()){
            it->second.erase(mac_addr);
            if(it->second.size()==0){
                vxlan_remote_macs.erase(rem_ip);
                return nas_mac_publish_remote_ip_event(entry,rem_ip,cps_api_oper_DELETE);
            }else{
                if(_check_if_flooding_mac(entry.entry_key.mac_addr)){
                    return nas_mac_publish_remote_ip_event(entry,rem_ip,cps_api_oper_SET);
                }
            }
        }
    }

    return true;

}

static bool _process_mac_entry(nas_mac_entry_t & entry){

    if(entry.os_configured){
        if( (nas_mac_update_entry_in_os(&entry,cps_api_oper_CREATE)) != STD_ERR_OK){
            return false;
        }
    }

    if(entry.npu_configured == true){
        if((nas_mac_create_entry_hw(&entry))!=STD_ERR_OK){
                return false;
        }
        if(entry.publish){
            nas_mac_send_event_notification(entry,NAS_MAC_ADD);
        }
    }

    return true;
}

static bool _nas_mac_update_hw(nas_mac_entry_t & entry, cps_api_operation_types_t op){

    if(op == cps_api_oper_DELETE){
        /*
         * Delete the MAC in npu
         */
        if(!_check_if_flooding_mac(entry.entry_key.mac_addr)){
            if(nas_mac_delete_entries_from_hw(&entry,NDI_MAC_DEL_SINGLE_ENTRY) != STD_ERR_OK){
            return false;
            }
        }
        return nas_mac_update_remote_macs_cache(entry,false);
    }else if (op == cps_api_oper_CREATE){

        if(_process_mac_entry(entry)){
            return nas_mac_update_remote_macs_cache(entry,true);
        }

    }else{
        // To see what needs to be done for update
    }

    return false;
}


static bool nas_mac_handle_remote_entry(nas_mac_entry_t & entry, cps_api_operation_types_t op){
    /*
     * check if the remote ip is known if not then publish an event to nas-intf
     * about new remote endpoit
     */
    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    vni_rem_ip_t rem_ip = { entry.endpoint_ip,entry.bridge_ifindex};
    auto it = known_rem_ips.find(rem_ip);
    if( it == known_rem_ips.end()){
        if(op == cps_api_oper_CREATE){
            nas_mac_publish_remote_ip_event(entry,rem_ip,cps_api_oper_CREATE);
            auto mac_it = vxlan_pending_macs.find(rem_ip);
            if(mac_it == vxlan_pending_macs.end()){
                nas_mac_list mac_l;
                mac_l.push_back(entry);
                vxlan_pending_macs[rem_ip] = mac_l;
            }else{
                mac_it->second.push_back(entry);
            }
        }
    }else {
        return _nas_mac_update_hw(entry,op);
    }

    return true;

}


static bool nas_mac_process_fdb_event(nas_mac_entry_t & entry, nas::attr_set_t & attr,
                                      cps_api_operation_types_t op){

    interface_ctrl_t i;
    memset(&i,0,sizeof(i));
    i.if_index = entry.bridge_ifindex;
    i.q_type = HAL_INTF_INFO_FROM_IF;

    if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
        return false;
    }

    if(i.int_type == nas_int_type_DOT1D_BRIDGE){
        entry.bridge_id = i.bridge_id;
    }
    attr.add(BASE_MAC_FORWARDING_TABLE_BR_NAME);

    if(!nas_mac_validate_params(attr,op)){
        return false;
    }

    entry.entry_type = NDI_MAC_ENTRY_TYPE_1D_REMOTE;
    return nas_mac_handle_remote_entry(entry,op);
}


bool nas_mac_process_os_event(nas_mac_entry_t & entry, nas::attr_set_t & attr, cps_api_operation_types_t op){


    if(attr.contains(BASE_MAC_TABLE_IFINDEX)){
        if(nas_mac_get_bridge_from_vtep(entry.ifindex,entry.bridge_ifindex)){
            return nas_mac_process_fdb_event(entry,attr,op);
        }else{
            std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
            _remote_pending_entry _e = { entry,attr,op};
            auto it = _remote_pending_entry_map.find(entry.ifindex);
            if(it == _remote_pending_entry_map.end()){
                _remote_entry_list _l;
                _l.push_back(_e);
                _remote_pending_entry_map[entry.ifindex] = _l;
            }
            _remote_pending_entry_map[entry.ifindex].push_back(_e);
        }
    }

    return true;
}


t_std_error nas_mac_cps_create_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;


    if ((rc = nas_mac_obj_to_entry(obj, &entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }

    if(entry.entry_type == NDI_MAC_ENTRY_TYPE_1Q || entry.entry_type == NDI_MAC_ENTRY_TYPE_1D_LOCAL){
        if(!_process_mac_entry(entry)){
            return STD_ERR(MAC,FAIL,0);
        }
    }else{
        if(!nas_mac_handle_remote_entry(entry,cps_api_oper_CREATE)){
            return STD_ERR(MAC,FAIL,0);
        }
    }



    return STD_ERR_OK;
}

static t_std_error nas_mac_update_entry(nas_mac_entry_t *entry){

    t_std_error rc;
    ndi_mac_entry_t ndi_mac_entry;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry));

    if(!nas_mac_fill_ndi_entry(ndi_mac_entry,*entry)){
        return STD_ERR(MAC,CFG,0);
    }

    if(entry->ifindex != 0){
        cps_api_operation_types_t op = cps_api_oper_DELETE;
        if(entry->os_configured==true){
            op = cps_api_oper_SET;
        }

        if((rc = nas_mac_update_entry_in_os(entry,op))!= STD_ERR_OK){
            return rc;
        }

        if(entry->npu_configured){
            /*
             * For 1D remote entry to move the mac to tunnel bridge port
             * SAI need two attributes one is new port and another one is
             * the remote ip address. Currently SAI only allows one attribute
             * to be updated at a time. So instead of calling update, need to
             * call create mac entry.
             */
            if(ndi_mac_entry.mac_entry_type == NDI_MAC_ENTRY_TYPE_1D_REMOTE){
                return ndi_create_mac_entry(&ndi_mac_entry);
            }
            if((rc = ndi_update_mac_entry(&ndi_mac_entry,NDI_MAC_ENTRY_ATTR_PORT_ID)) != STD_ERR_OK){
                return rc;
            }
        }
    }

    if(entry->pkt_action != 0){
        if((rc = ndi_update_mac_entry(&ndi_mac_entry,NDI_MAC_ENTRY_ATTR_PKT_ACTION)) != STD_ERR_OK){
            return rc;
        }
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_cps_update_entry (cps_api_object_t obj){

    t_std_error rc;
    nas_mac_entry_t entry;

    if ((rc = nas_mac_obj_to_entry(obj, &entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(DEBUG, "Object to Entry conversion failed ");
        return rc;
    }
    return nas_mac_update_entry(&entry);
}


static bool is_filter_type_present (nas_mac_entry_t *entry, del_filter_type_t filter_type) {
    hal_mac_addr_t zero_mac;
    memset(&zero_mac, 0, sizeof(hal_mac_addr_t));
    switch (filter_type) {
        case DEL_VLAN_FILTER:
            if (entry->entry_key.vlan_id != 0 || entry->bridge_id != 0) {
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


static void nas_mac_fill_flush_entry (nas_mac_cps_event_t & flush_entry) {

    bool vlan_filter_on, mac_filter_on, if_filter_on = false;
    bool single_entry_delete = false;
    ndi_mac_delete_type_t del_type = NDI_MAC_DEL_ALL_ENTRIES;

    vlan_filter_on = is_filter_type_present(&flush_entry.entry, DEL_VLAN_FILTER);
    mac_filter_on = is_filter_type_present(&flush_entry.entry, DEL_MAC_FILTER);
    if_filter_on = is_filter_type_present(&flush_entry.entry, DEL_IF_FILTER);
    single_entry_delete  = ((vlan_filter_on) && (mac_filter_on));

    if(single_entry_delete){
        if(flush_entry.entry.os_configured == true){
            nas_mac_update_entry_in_os(&flush_entry.entry,cps_api_oper_DELETE);
            if(flush_entry.entry.npu_configured == false){
                return;
            }
        }
        del_type = NDI_MAC_DEL_SINGLE_ENTRY;
    }else if (if_filter_on) {
        del_type = NDI_MAC_DEL_BY_PORT;
        if(vlan_filter_on) del_type = NDI_MAC_DEL_BY_PORT_VLAN;
    } else if (vlan_filter_on) {
        del_type = NDI_MAC_DEL_BY_VLAN;
    }


    flush_entry.op_type = NAS_MAC_DEL;
    flush_entry.del_type = del_type;
    return;
}

/*  TODO now separate thread for flush handling has been removed.
 *  Clean-up needs to be done. */
t_std_error nas_mac_send_cps_event(nas_mac_cps_event_t * entries, int count){


    for (int i =0; i < count; i ++) {

        nas_mac_clear_hw_mac(entries[i]);
    }
    return STD_ERR_OK;
}


t_std_error nas_mac_cps_delete_entry (cps_api_object_t obj){

    nas_mac_cps_event_t flush_entry;
    t_std_error rc;
    if ((rc = nas_mac_obj_to_entry(obj, &flush_entry.entry)) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "Object to Entry conversion failed ");
        return rc;
    }

    if(flush_entry.entry.entry_type == NDI_MAC_ENTRY_TYPE_1Q ||
        flush_entry.entry.entry_type == NDI_MAC_ENTRY_TYPE_1D_LOCAL){
        nas_mac_fill_flush_entry(flush_entry);
        return nas_mac_send_cps_event(&flush_entry,1);
    }else{
        if(!nas_mac_handle_remote_entry(flush_entry.entry,cps_api_oper_DELETE)){
            return STD_ERR(MAC,FAIL,0);
        }
    }
    return STD_ERR_OK;

}


t_std_error nas_mac_flush_vlan_entries_of_port(uint32_t vlan, hal_ifindex_t port_index) {

    nas_mac_cps_event_t flush_entry;
    flush_entry.entry.ifindex = port_index;
    flush_entry.entry.entry_key.vlan_id = vlan;
    nas_mac_fill_flush_entry(flush_entry);
    return nas_mac_send_cps_event(&flush_entry,1);
}

static bool _get_ifindex_from_name(const char *name,hal_ifindex_t & index){
    interface_ctrl_t i;
    memset(&i,0,sizeof(interface_ctrl_t));
    strncpy(i.if_name,name,sizeof(i.if_name)-1);
    i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
        return false;
    }
    index = i.if_index;
    return true;
}

static bool _port_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                cps_api_attr_id_t * ids,size_t ids_len){
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFINDEX;
    cps_api_object_attr_t ifindex_attr = cps_api_object_e_get(obj,ids,sizeof(ids[0]));
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFNAME;
    cps_api_object_attr_t ifname_attr = cps_api_object_e_get(obj,ids,ids_len);
    entry.entry_type = NDI_MAC_ENTRY_TYPE_1Q;
    if(ifindex_attr){
        entry.ifindex = cps_api_object_attr_data_u32(ifindex_attr);
        return true;
    }

    if(ifname_attr){
        const char * name = (const char *)cps_api_object_attr_data_bin(ifname_attr);
        return _get_ifindex_from_name(name,entry.ifindex);
    }
    return false;
}

static bool _vlan_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                cps_api_attr_id_t * ids,size_t ids_len){
     ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_VLAN;
     entry.entry_type = NDI_MAC_ENTRY_TYPE_1Q;
     cps_api_object_attr_t vlan_attr = cps_api_object_e_get(obj,ids,ids_len);
     if(vlan_attr){
         entry.entry_key.vlan_id = cps_api_object_attr_data_uint(vlan_attr);
         return true;
     }
    return false;
}

static bool _subport_bridge_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                cps_api_attr_id_t * ids,size_t ids_len) {
    /* Check for bridge name . For untagged .1d or attached vlan brports vlan id sent is 0 */
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_BR_NAME;
    cps_api_object_attr_t br_attr = cps_api_object_e_get(obj,ids,ids_len);
    if (br_attr) {
        const char *name = (const char *) cps_api_object_attr_data_bin(br_attr);
        interface_ctrl_t i;
        memset(&i,0,sizeof(i));
        safestrncpy(i.if_name,name,sizeof(i.if_name));
        i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
            EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
              "Can't get interface control information for %s",name);
            return false;
        }
        /* Find VLAN id for this bridge */
        nas_mac_get_1d_br_untag_vid(i.if_index, entry.entry_key.vlan_id);
        EV_LOGGING(L2MAC, DEBUG, "NAS-MAC", "Untagged subport flush :bridge ifindex %d ,untagged vlan id %d \n",
                 i.if_index, entry.entry_key.vlan_id);
        return true;
     } else {
         NAS_MAC_LOG(ERR, " Untagged Subport flush : with no bridge name");
         return false;
     }

}

static bool _port_vlan_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                    cps_api_attr_id_t *ids,size_t ids_len){

    return (_port_flush_handler(entry,obj,ids,ids_len) && _vlan_flush_handler(entry,obj,ids,ids_len));
}

static bool _port_bridge_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                      cps_api_attr_id_t *ids,size_t ids_len) {

    return (_port_flush_handler(entry,obj,ids,ids_len) && _subport_bridge_handler(entry,obj,ids,ids_len));


}

static bool _port_vlan_subport_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                    cps_api_attr_id_t *ids,size_t ids_len){

    if ( (_port_flush_handler(entry,obj,ids,ids_len) && _vlan_flush_handler(entry,obj,ids,ids_len)) ) {
        entry.entry_type = NDI_MAC_ENTRY_TYPE_1D_LOCAL;
    } else {
        return false;
    }
    return true;
}


static bool _bridge_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                    cps_api_attr_id_t * ids,size_t ids_len){
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_BR_NAME;
    cps_api_object_attr_t br_attr = cps_api_object_e_get(obj,ids,ids_len);
    entry.entry_type = NDI_MAC_ENTRY_TYPE_1D_LOCAL;
    if(br_attr){
        const char *name = (const char *) cps_api_object_attr_data_bin(br_attr);
        interface_ctrl_t i;
        memset(&i,0,sizeof(i));
        strncpy(i.if_name,name,sizeof(i.if_name)-1);
        i.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        if (dn_hal_get_interface_info(&i)!=STD_ERR_OK){
           EV_LOGGING(L2MAC, DEBUG, "NAS-MAC",
                   "Can't get interface control information for %s",name);
           return false;
        }

        if(i.int_type == nas_int_type_DOT1D_BRIDGE){
           entry.bridge_ifindex = i.if_index;
           entry.bridge_id = i.bridge_id;
           return true;
        }else{
           NAS_MAC_LOG(ERR,"Failed to find Dot1d bridge %s information",name);
           return false;
        }
    }
    return false;
}


static bool _bridge_endpoint_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                            cps_api_attr_id_t *ids,size_t ids_len){
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_ENDPOINT_IP;
    cps_api_object_attr_t ip_attr = cps_api_object_e_get(obj,ids,ids_len);
    if((_bridge_flush_handler(entry,obj,ids,ids_len)) && ip_attr){
        memcpy(&entry.endpoint_ip,(void *)cps_api_object_attr_data_bin(ip_attr),
                                    sizeof(entry.endpoint_ip));
        char ip_addr_str[HAL_INET6_TEXT_LEN];
        if(std_ip_to_string(&entry.endpoint_ip,ip_addr_str,HAL_INET6_LEN) == NULL){
            NAS_MAC_LOG(ERR,"Invalid IP Address in Endpoint Event notification");
            return false;
        }
        entry.entry_type = NDI_MAC_ENTRY_TYPE_1D_REMOTE;


        return true;
    }
    return false;
}


static bool _all_flush_handler(nas_mac_entry_t & entry, cps_api_object_t obj,
                                cps_api_attr_id_t * ids,size_t ids_len){
    return true;
}


static auto _flush_fn_map = * new std::unordered_map<BASE_MAC_MAC_FLUSH_TYPE_t, bool (*)
                (nas_mac_entry_t & _entry,cps_api_object_t obj,cps_api_attr_id_t *ids,
                size_t ids_len ),std::hash<int>>
{
    {BASE_MAC_MAC_FLUSH_TYPE_PORT,_port_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN,_vlan_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN_PORT,_port_vlan_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE,_bridge_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE_ENDPOINT_IP,_bridge_endpoint_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_ALL,_all_flush_handler},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN_PORT_SUBPORT,_port_vlan_subport_flush_handler}, /*  for tagged 1d bridge member  */
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE_PORT, _port_bridge_flush_handler}, /* for untagged subport */


};

static auto _nas_to_ndi_flush_type =  * new std::unordered_map<BASE_MAC_MAC_FLUSH_TYPE_t,
                                                                ndi_mac_delete_type_t,std::hash<int>>{
    {BASE_MAC_MAC_FLUSH_TYPE_PORT,NDI_MAC_DEL_BY_PORT},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN,NDI_MAC_DEL_BY_VLAN},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN_PORT,NDI_MAC_DEL_BY_PORT_VLAN},
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE,NDI_MAC_DEL_BY_BRIDGE},
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE_ENDPOINT_IP,NDI_MAC_DEL_BY_BRIDGE_ENDPOINT_IP},
    {BASE_MAC_MAC_FLUSH_TYPE_VLAN_PORT_SUBPORT,NDI_MAC_DEL_BY_PORT_VLAN_SUBPORT},
    {BASE_MAC_MAC_FLUSH_TYPE_ALL,NDI_MAC_DEL_ALL_ENTRIES},
    {BASE_MAC_MAC_FLUSH_TYPE_BRIDGE_PORT ,NDI_MAC_DEL_BY_PORT_VLAN_SUBPORT},
};


static bool nas_mac_flush_remote_ip(std::vector<nas_mac_cps_event_t> & flush_queue, cps_api_object_t obj,
                                cps_api_attr_id_t * ids, size_t ids_len){
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_ENDPOINT_IP_ADDR;
    cps_api_object_attr_t ip_attr = cps_api_object_e_get(obj,ids,ids_len);
    ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_ENDPOINT_IP_ADDR_FAMILY;
    cps_api_object_attr_t af_attr = cps_api_object_e_get(obj,ids,ids_len);
    hal_ip_addr_t ip_addr;
    if(!ip_attr || !af_attr){
        return false;
    }

    ip_addr.af_index = cps_api_object_attr_data_u32(af_attr);

    if(ip_addr.af_index == AF_INET){
        memcpy(&ip_addr.u.ipv4,cps_api_object_attr_data_bin(ip_attr),
                sizeof(ip_addr.u.ipv4));
    }else{
        memcpy(&ip_addr.u.ipv6,cps_api_object_attr_data_bin(ip_attr),
                sizeof(ip_addr.u.ipv6));
    }

    char ip_addr_str[HAL_INET6_TEXT_LEN];
    if(std_ip_to_string(&ip_addr,ip_addr_str,HAL_INET6_LEN) == NULL){
        NAS_MAC_LOG(ERR,"Invalid IP Address in Endpoint IP flush");
        return false;
    }

    nas_mac_cps_event_t flush_entry;
    flush_entry.op_type = NAS_MAC_DEL;
    flush_entry.del_type = NDI_MAC_DEL_BY_BRIDGE_ENDPOINT_IP;
    flush_entry.entry.entry_type = NDI_MAC_ENTRY_TYPE_1D_REMOTE;
    memcpy(&flush_entry.entry.endpoint_ip,&ip_addr,sizeof(hal_ip_addr_t));
    std::string ip_str(ip_addr_str);

    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    for(auto it : tunnel_endpoint_map){
        if(it.first.ip == ip_str){
            flush_entry.entry.bridge_ifindex = it.first.br_index;
            flush_queue.push_back(flush_entry);
            EV_LOGGING(L2MAC,INFO,"FLUSH","Flushing for IP %s and bridge %d",ip_addr_str,it.first.br_index);
        }
    }

    return true;
}


static bool nas_mac_flush_entries(cps_api_object_t obj,const cps_api_object_it_t & it){

    cps_api_object_it_t it_lvl_1 = it;
    cps_api_attr_id_t ids[3] = {BASE_MAC_FLUSH_INPUT_FILTER,0, BASE_MAC_FLUSH_INPUT_FILTER_VLAN };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    nas_mac_cps_event_t flush_entry;
    std::vector<nas_mac_cps_event_t> flush_queue;

    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        ids[1] = cps_api_object_attr_id (it_lvl_1.attr);
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_FLUSH_TYPE;
        cps_api_object_attr_t type_attr = cps_api_object_e_get(obj,ids,ids_len);

        if(!type_attr){
            continue;
        }

        BASE_MAC_MAC_FLUSH_TYPE_t _flush_type = (BASE_MAC_MAC_FLUSH_TYPE_t)
                                                 cps_api_object_attr_data_uint(type_attr);

        if(_flush_type == BASE_MAC_MAC_FLUSH_TYPE_ENDPOINT_IP){
            nas_mac_flush_remote_ip(flush_queue,obj,ids,ids_len);
        }else{
            auto it = _flush_fn_map.find(_flush_type);
            if(it == _flush_fn_map.end()){
                NAS_MAC_LOG(ERR,"Invalid flush type passed %d",_flush_type);
                continue;
            }

            if(_flush_fn_map[_flush_type](flush_entry.entry,obj,ids,ids_len)){
                flush_entry.op_type = NAS_MAC_DEL;
                flush_entry.del_type = _nas_to_ndi_flush_type[_flush_type];
                flush_queue.push_back(flush_entry);
            }
        }
    }

    return nas_mac_send_cps_event(&flush_queue[0],flush_queue.size()) == STD_ERR_OK ? true : false;

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

    nas_mac_cps_event_t flush_entry;
    flush_entry.entry.ifindex = ifindex;
    nas_mac_fill_flush_entry(flush_entry);
    return nas_mac_send_cps_event(&flush_entry,1);
}

static auto ndi_to_nas_mac_ev = new std::unordered_map<unsigned int,unsigned int>
{
    {NDI_MAC_EVENT_LEARNED, NAS_MAC_ADD},
    {NDI_MAC_EVENT_AGED,NAS_MAC_DEL},
    {NDI_MAC_EVENT_FLUSHED,NAS_MAC_FLUSH},
    {NDI_MAC_EVENT_MOVED,NAS_MAC_MOVE}
};

void nas_mac_event_notification_cb(npu_id_t npu_id, ndi_mac_event_type_t ev_type, ndi_mac_entry_t *mac_entry, bool is_lag_index)
{
    if(ev_type == NDI_MAC_EVENT_INVALID) return;

    nas_mac_npu_event_t  mac_event;
    interface_ctrl_t intf_ctrl;
    hal_ifindex_t lag_index;
    mac_event.entry.entry_type = mac_entry->mac_entry_type;

    if(mac_event.entry.entry_type == NDI_MAC_ENTRY_TYPE_1D_REMOTE){
           memcpy(&mac_event.entry.endpoint_ip,&mac_entry->endpoint_ip,sizeof(mac_event.entry.endpoint_ip));
           mac_event.entry.endpoint_ip_id = mac_entry->endpoint_ip_port;
    }else{
        if (!is_lag_index) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

            intf_ctrl.q_type = HAL_INTF_INFO_FROM_PORT;
            intf_ctrl.npu_id = mac_entry->port_info.npu_id;
            intf_ctrl.port_id = mac_entry->port_info.npu_port;

            if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
                NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
                return;
            }
            mac_event.entry.ifindex = intf_ctrl.if_index;
        } else {
            if (nas_get_lag_if_index(mac_entry->ndi_lag_id,&lag_index) != STD_ERR_OK) {
                NAS_MAC_LOG(ERR,"Failed to get Lag ifindex for ndi lag id 0x%x",mac_entry->ndi_lag_id);
                return;
            }
            mac_event.entry.ifindex = lag_index;
        }
    }

    mac_event.entry.entry_key.vlan_id = mac_entry->vlan_id;
    memcpy(mac_event.entry.entry_key.mac_addr, mac_entry->mac_addr, sizeof(hal_mac_addr_t));
    mac_event.entry.pkt_action = mac_entry->action;
    mac_event.entry.bridge_id = mac_entry->bridge_id;



    auto it = ndi_to_nas_mac_ev->find(ev_type);
    if(it != ndi_to_nas_mac_ev->end()){
        mac_event.op_type = (nas_l2_mac_op_t)it->second;
    }else{
        NAS_MAC_LOG(ERR,"Invalid NDI event type %d",ev_type);
        return;
    }


    nas_mac_send_event_notification(mac_event.entry,mac_event.op_type);
}


bool nas_get_mac_entry_from_ndi(nas_mac_entry_t & entry){
    /*
     * For now you can only do a single entry get based on the key of the entry
     */

    ndi_mac_entry_t ndi_entry;
    memset(&ndi_entry,0,sizeof(ndi_entry));
    ndi_entry.vlan_id= entry.entry_key.vlan_id;
    memcpy(&ndi_entry.mac_addr,&entry.entry_key.mac_addr,sizeof(ndi_entry.mac_addr));

    if(ndi_get_mac_entry_attr(&ndi_entry) != STD_ERR_OK){
        NAS_MAC_LOG(ERR,"Failed to get MAC entry from NDI");
        return false;
    }

    entry.pkt_action = ndi_entry.action;
    entry.is_static = ndi_entry.is_static;
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    if(ndi_entry.ndi_lag_id){

    if (nas_get_lag_if_index(ndi_entry.ndi_lag_id,&entry.ifindex) != STD_ERR_OK) {
            NAS_MAC_LOG(ERR,"Failed to get Lag ifindex for ndi lag id 0x%lx",ndi_entry.ndi_lag_id);
            return false;
        }
    } else {
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_PORT;
        intf_ctrl.npu_id = ndi_entry.port_info.npu_id;
        intf_ctrl.port_id = ndi_entry.port_info.npu_port;

        if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
           NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
           return false;
        }
        entry.ifindex = intf_ctrl.if_index;
    }

    return true;
}


static bool _process_pending_macs(vni_rem_ip_t & _rem_ip){
    auto it = vxlan_pending_macs.find(_rem_ip);
    if (it == vxlan_pending_macs.end()){
        NAS_MAC_LOG(ERR,"Failed to find pending mac for bridge %d",_rem_ip.br_index);
        return false;
    }

    for (auto macs : it->second){
        /*
         * flooding macs doesn't need to be pushed to npu
         */
        if(_check_if_flooding_mac(macs.entry_key.mac_addr)){
            nas_mac_update_remote_macs_cache(macs,true);
            continue;
        }

        if(nas_mac_create_entry_hw(&macs) == STD_ERR_OK){
            nas_mac_update_remote_macs_cache(macs,true);
        }
    }

    vxlan_pending_macs.erase(it);

    return true;
}

bool _process_remote_endpint(const char *  vtep_name, hal_ip_addr_t & ip_addr, ndi_obj_id_t tunnel_id,bool add){

    if(!tunnel_id){
        return false;
    }

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    strncpy(intf_ctrl.if_name,vtep_name,sizeof(intf_ctrl.if_name)-1);

    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
        return false;
    }

    if(intf_ctrl.int_type != nas_int_type_VXLAN){
        return true;
    }

    hal_ifindex_t bridge_index=0;
    if(!nas_mac_get_bridge_from_vtep(intf_ctrl.if_index,bridge_index)){
        NAS_MAC_LOG(ERR,"Failed to find bridge for vtep %d",intf_ctrl.if_index);
        return false;
    }

    vni_rem_ip_t _rem_ip = {ip_addr,bridge_index};

    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);

    if(add){
        known_rem_ips.insert(_rem_ip);
        tunnel_endpoint_map[_rem_ip]=tunnel_id;
        tunnel_id_to_vtep_map[tunnel_id]=vtep_name;
        _process_pending_macs(_rem_ip);
    }else{
        known_rem_ips.erase(_rem_ip);
        tunnel_id_to_vtep_map.erase(tunnel_id);
        tunnel_endpoint_map.erase(_rem_ip);
    }


    return true;
}

static bool _process_pending_vtep_mac(hal_ifindex_t vtep_index, hal_ifindex_t br_index){
    std::lock_guard<std::recursive_mutex> _lk(_vxlan_mtx);
    auto it = _remote_pending_entry_map.find(vtep_index);
    if(it == _remote_pending_entry_map.end()){
        return true;
    }
    for(auto _e : it->second){
        _e.entry.bridge_ifindex = br_index;
        nas_mac_process_fdb_event(_e.entry,_e.attrs,_e.op);
    }
    _remote_pending_entry_map.erase(it);
    return true;
}

/*  Handle vtep member addition to a 1D bridge. Add all pending MAC address configured
 *  on the vxlan interface in the NPU
 *  */
bool _process_bridge_event(const char * br_name, const char * vtep_name, bool add){
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    strncpy(intf_ctrl.if_name,vtep_name,sizeof(intf_ctrl.if_name)-1);
    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "NDI MAC Get interface failed.");
        return false;
    }

    /*  IF not VTEP member then ignore the event  */
    if(intf_ctrl.int_type != nas_int_type_VXLAN){
        return true;
    }
    hal_ifindex_t vtep_index = intf_ctrl.if_index;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    NAS_MAC_LOG(INFO, " Handle VTEP member %s addition to the bridge %s", vtep_name, br_name);

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    strncpy(intf_ctrl.if_name,br_name,sizeof(intf_ctrl.if_name)-1);
    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        NAS_MAC_LOG(ERR, "NDI MAC Get interface failed for bridge %s.", br_name);
        return false;
    }
    hal_ifindex_t br_index = intf_ctrl.if_index;

    std::lock_guard<std::mutex> _lk(_bridge_mtx);
    if(add){
        vxlan_bridge_map[vtep_index]=br_index;
        _process_pending_vtep_mac(vtep_index,br_index);
    }else{
        vxlan_bridge_map.erase(vtep_index);
    }

    return true;

}
