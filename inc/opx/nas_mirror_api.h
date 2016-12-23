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
 * filename: nas_mirror_api.h
 */


#ifndef NAS_MIRROR_API_H
#define NAS_MIRROR_API_H

#include "dell-base-mirror.h"
#include "dell-base-common.h"
#include "nas_ndi_mirror.h"
#include "ds_common_types.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "event_log.h"

#include <string.h>
#include <vector>
#include <unordered_map>

#define NAS_MIRROR_LOG(type, msg, ...)\
                       EV_LOGGING(NAS_L2,type,"NAS-MIRROR",msg, ##__VA_ARGS__)

typedef unsigned int nas_mirror_id_t;

//Map to maintain src interface index and its direction
typedef std::unordered_map<hal_ifindex_t,BASE_CMN_TRAFFIC_PATH_t>nas_mirror_src_intf_map_t;
typedef std::unordered_map<hal_ifindex_t,BASE_CMN_TRAFFIC_PATH_t>::iterator nas_mirror_src_intf_map_it;
typedef std::pair<hal_ifindex_t,BASE_CMN_TRAFFIC_PATH_t> nas_mirror_src_intf_pair;


class nas_mirror_entry {

public:


    void set_id(nas_mirror_id_t id) { nas_mirror_session_id = id ;}
    void set_dst_intf(hal_ifindex_t ifindex){ dst_intf = ifindex ; }
    bool add_src_intf(hal_ifindex_t ifindex ,BASE_CMN_TRAFFIC_PATH_t dir);
    void rem_src_intf(hal_ifindex_t ifindex){
        nas_mirror_src_intf.erase(ifindex);
    }

    void del_src_port(ndi_mirror_src_port_t port);
    void set_flow(bool state){ is_mirror_flow_enabled = true;}
    void set_vlan(hal_vlan_id_t id){ndi_mirror_entry.vlan_id = id ;}
    void set_src_ip(uint32_t ip_addr){ndi_mirror_entry.src_ip.u.v4_addr = ip_addr ;}
    void set_dst_ip(uint32_t ip_addr){ndi_mirror_entry.dst_ip.u.v4_addr = ip_addr ;}
    void set_src_mac(void * mac){memcpy(ndi_mirror_entry.src_mac, mac, sizeof(hal_mac_addr_t)) ;}
    void set_dst_mac(void * mac){memcpy(ndi_mirror_entry.dst_mac, mac, sizeof(hal_mac_addr_t)) ;}
    void set_mode(BASE_MIRROR_MODE_t mode){ndi_mirror_entry.mode = mode ;}
    void set_ndi_id(ndi_mirror_id_t id){ndi_mirror_entry.ndi_mirror_id = id ;}
    void set_dst_port(npu_id_t npu_id,npu_port_t port){
        ndi_mirror_entry.dst_port.npu_id = npu_id;
        ndi_mirror_entry.dst_port.npu_port = port;
        ndi_mirror_entry.is_dest_lag = false;
    }
    void set_ndi_lag_id(npu_id_t npu_id,ndi_obj_id_t id){
        ndi_mirror_entry.dst_port.npu_id = npu_id;
        ndi_mirror_entry.is_dest_lag = true;
        ndi_mirror_entry.ndi_lag_id = id;
    };
    bool update_src_intf_map(nas_mirror_src_intf_map_t & intf_map);
    bool remove_src_intf();
    nas_mirror_id_t get_id() { return nas_mirror_session_id;}
    hal_ifindex_t get_dst_intf(){ return dst_intf ; }
    const nas_mirror_src_intf_map_t * get_src_intf_map(){ return &nas_mirror_src_intf ;}
    bool get_flow(){ return is_mirror_flow_enabled ;}
    hal_vlan_id_t get_vlan_id(){ return ndi_mirror_entry.vlan_id ;}
    hal_ip_addr_t  * get_src_ip(){ return &ndi_mirror_entry.src_ip ;}
    hal_ip_addr_t  * get_dst_ip(){ return &ndi_mirror_entry.dst_ip ;}
    hal_mac_addr_t * get_src_mac(){return &ndi_mirror_entry.src_mac;}
    hal_mac_addr_t * get_dst_mac(){return &ndi_mirror_entry.dst_mac;}
    BASE_MIRROR_MODE_t get_mode(){ return ndi_mirror_entry.mode ;}
    ndi_mirror_id_t get_ndi_id(){ return ndi_mirror_entry.ndi_mirror_id ;}
    const ndi_port_t * get_dst_port(){ return &ndi_mirror_entry.dst_port; }
    const npu_id_t get_npu_id(){return ndi_mirror_entry.dst_port.npu_id ; }
    ndi_mirror_entry_t * get_ndi_entry(){ return &ndi_mirror_entry ;}


private:
    nas_mirror_id_t nas_mirror_session_id;             //NAS Mirror id
    hal_ifindex_t  dst_intf;                        //Destination Mirror Interface
    nas_mirror_src_intf_map_t nas_mirror_src_intf;  // Source Mirror Interface MAp
    bool is_mirror_flow_enabled=false;                //Is it a flow based session
    ndi_mirror_entry_t ndi_mirror_entry;            // NDI Mirror Entry
};


// Mirror Entry Map
typedef std::unordered_map<nas_mirror_id_t,nas_mirror_entry > nas_mirror_table_t;
typedef std::unordered_map<nas_mirror_id_t,nas_mirror_entry >::iterator nas_mirror_table_it;
typedef std::pair<nas_mirror_id_t, nas_mirror_entry > nas_mirror_table_pair;


/*
 * Initialize Mirroring Module
 */
t_std_error nas_mirroring_init(cps_api_operation_handle_t handle);


/*
 * Create a New Mirroring Session from CPS Object
 */
t_std_error nas_mirror_create_session(cps_api_object_t obj);


/*
 * Delete an existing Mirroring Session from CPS Object
 */
t_std_error nas_mirror_delete_session(cps_api_object_t  obj, nas_mirror_id_t id);


/*
 * Update the existing Mirroring Session
 */
t_std_error nas_mirror_set_session(cps_api_object_t obj,nas_mirror_id_t id);


/*
 * Get all the Mirroring session information and fill it to cps object list
 */
t_std_error nas_mirror_get_all_info(cps_api_object_list_t list);


/*
 * Get a specific Mirror session information and fill it to cps object list
 */
t_std_error nas_mirror_get_session_info(cps_api_object_list_t list, nas_mirror_id_t id);


#endif /* NAS_MIRROR_API_H */
