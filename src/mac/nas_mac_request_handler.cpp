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

#include "nas_mac_api.h"
#include "std_error_codes.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mac.h"
#include "nas_if_utils.h"
#include "std_socket_tools.h"
#include "std_file_utils.h"
#include "std_select_tools.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "cps_api_events.h"

#include <unistd.h>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>


static auto nas_mac_request_queue = new nas_mac_cps_event_queue_t;
static auto mac_delete_queue = new nas_mac_cps_event_queue_t;
bool clear_all = false;
static auto nas_mac_event_queue = new nas_mac_npu_event_queue_t;
static size_t max_obj_pub_thresold = 1000;
static int event_fd[2];
static unsigned int client_count = 0;
static int max_sock_fd;
static int max_pending_con = 0;
static const char * mac_socket_path = "/tmp/nas_mac_socket";
static fd_set  mac_fd_set;
static fd_set  mac_master_fd_set;
static const unsigned int nas_mac_max_connect_retries = 100;
static long unsigned int _flush_count[NDI_MAC_DEL_INVALID_TYPE+1] = {0};
static std::condition_variable _cv;
static std::mutex _mtx;
static bool _server_ready = false;


static auto port_flush_queue = new std::unordered_map <hal_ifindex_t, nas_mac_cps_event_t>;
static auto vlan_flush_queue = new std::unordered_map <hal_vlan_id_t, nas_mac_cps_event_t>;
static auto bridge_flush_queue = new std::unordered_map<hal_ifindex_t, nas_mac_cps_event_t>;
static auto bridge_endpoint_queue = new std::map<vni_rem_ip_t, nas_mac_cps_event_t>;

typedef struct port_vlan_flush{
    hal_ifindex_t ifindex;
    hal_vlan_id_t vlan_id;

    bool operator == (port_vlan_flush const & rhs) const{
        if(ifindex != rhs.ifindex) return false;
        if(vlan_id != rhs.vlan_id) return false;
        return true;
    }
}port_vlan_flush_t;


struct port_vlan_flush_hash{
     std::size_t operator() (port_vlan_flush_t const & entry) const {
        std::size_t ifindex_hash = std::hash<unsigned int>()(entry.ifindex);
        std::size_t vlan_hash = std::hash<unsigned int>()(entry.vlan_id);
        return (ifindex_hash<<1)^(vlan_hash <<1);
    }
};

static auto port_vlan_flush_queue = new std::unordered_map<port_vlan_flush_t,
                                    nas_mac_cps_event_t, port_vlan_flush_hash>;

nas_mac_npu_event_queue_t & nas_mac_get_npu_event_queue(){
    return *nas_mac_event_queue;
}

void nas_mac_flush_count_dump(void){
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","Port flush count %llu",_flush_count[NDI_MAC_DEL_BY_PORT]);
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","vlan flush count %llu",_flush_count[NDI_MAC_DEL_BY_VLAN]);
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","Port vlan flush count %llu",_flush_count[NDI_MAC_DEL_BY_PORT_VLAN]);
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","Bridge flush count %llu",_flush_count[NDI_MAC_DEL_BY_BRIDGE]);
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","Bridge/endpoint flush count %llu",
            _flush_count[NDI_MAC_DEL_BY_BRIDGE_ENDPOINT_IP]);
    EV_LOGGING(L2MAC,NOTICE,"FLUSH-COUNT","Total flush count %llu",_flush_count[NDI_MAC_DEL_INVALID_TYPE]);
}

static t_std_error nas_mac_read_cps_notification(int fd, const size_t count,nas_mac_cps_event_queue_t & flush_list){

    t_std_error rc;
    int len = sizeof(nas_mac_cps_event_t) * count;
    std::vector<nas_mac_cps_event_t> mac_cps_ev_vec;
    mac_cps_ev_vec.resize(count);

    if(std_read(fd,&mac_cps_ev_vec[0],len,true,&rc) != len){
        EV_LOGGING(L2MAC,ERR,"L2-FLUSH-NOT","Failed to read flush_req");
        return rc;
    }

    for(unsigned int ix = 0 ; ix < count ; ++ix){
        flush_list.push_back(mac_cps_ev_vec[ix]);
    }

    return STD_ERR_OK;
}


static t_std_error nas_mac_read_npu_notification(int fd, const size_t count,nas_mac_npu_event_queue_t & event_list){

    t_std_error rc;
    int len = sizeof(nas_mac_npu_event_t) * count;
    std::vector<nas_mac_npu_event_t> mac_npu_event_vec;
    mac_npu_event_vec.resize(count);

    if(std_read(fd,&mac_npu_event_vec[0],len,true,&rc) != len){
        EV_LOGGING(L2MAC,ERR,"L2-FLUSH-NOT","Failed to read npu notification");
        return rc;
    }

    for(unsigned int ix = 0 ; ix < count ; ++ix){
        event_list.push_back(mac_npu_event_vec[ix]);
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_delete_entries_from_hw(nas_mac_entry_t *entry,
                                           ndi_mac_delete_type_t del_type
                                           ) {
    t_std_error rc = STD_ERR_OK;
    ndi_obj_id_t obj_id;
    interface_ctrl_t intf_ctrl;

    ndi_mac_entry_t ndi_mac_entry;
    memset(&ndi_mac_entry, 0, sizeof(ndi_mac_entry_t));


    if(del_type == NDI_MAC_DEL_BY_BRIDGE || entry->bridge_ifindex){
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = entry->bridge_ifindex;
        if((rc = dn_hal_get_interface_info(&intf_ctrl)) == STD_ERR_OK){
            ndi_mac_entry.bridge_id = intf_ctrl.bridge_id;
        }else{
            NAS_MAC_LOG(ERR,"Failed to find bridge id for bridge %d",entry->bridge_ifindex);
            return rc;
        }

    }

    if(del_type == NDI_MAC_DEL_BY_BRIDGE_ENDPOINT_IP){
        vni_rem_ip_t _rem_ip = {entry->endpoint_ip,entry->bridge_ifindex};
        if(!_get_endpoint_tunnel_id(_rem_ip, ndi_mac_entry.endpoint_ip_port)){
            return STD_ERR(MAC,FAIL,0);
        }

    }

    if ((del_type == NDI_MAC_DEL_BY_PORT) || (del_type == NDI_MAC_DEL_BY_PORT_VLAN) ||
        (del_type == NDI_MAC_DEL_BY_PORT_VLAN_SUBPORT))
    {
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = entry->ifindex;

        if ((rc = dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
             NAS_MAC_LOG(ERR, "Get interface info failed for if index 0x%x.", entry->ifindex);
             return rc;
        }
        if(intf_ctrl.int_type == nas_int_type_LAG)
        {
           if(nas_get_lag_id_from_if_index(entry->ifindex, &obj_id) == STD_ERR_OK)
           {
              ndi_mac_entry.ndi_lag_id = obj_id;
           }
        }
        else
        {
           ndi_mac_entry.npu_id = 0; /* TODO: Handle multiple NPU scenerio */
           ndi_mac_entry.port_info.npu_id = intf_ctrl.npu_id;
           ndi_mac_entry.port_info.npu_port = intf_ctrl.port_id;
        }
    }

    ndi_mac_entry.vlan_id = entry->entry_key.vlan_id;
    ndi_mac_entry.mac_entry_type = entry->entry_type;

    if (del_type == NDI_MAC_DEL_SINGLE_ENTRY) {
        memcpy(ndi_mac_entry.mac_addr, entry->entry_key.mac_addr, sizeof(hal_mac_addr_t));
    }
    ndi_mac_entry.is_static = entry->is_static;

    if ((rc = ndi_delete_mac_entry(&ndi_mac_entry, del_type, true) != STD_ERR_OK)) {
        NAS_MAC_LOG(ERR, "Error deleting NDI MAC entry with vlan id %d",
            entry->entry_key.vlan_id);
        return rc;
    }

    if(del_type != NDI_MAC_DEL_SINGLE_ENTRY){
        nas_mac_publish_flush_event(del_type,entry);
    }

    _flush_count[del_type]+=1;
    _flush_count[NDI_MAC_DEL_INVALID_TYPE]+=1;


    return STD_ERR_OK;
}


static void nas_mac_clear_hw_mac(nas_mac_cps_event_t & req_entry){

    if(nas_mac_delete_entries_from_hw(&(req_entry.entry),
                                req_entry.del_type) != STD_ERR_OK){
        NAS_MAC_LOG(ERR,"Failed to remove MAC entry from hardware");
    }


    if(req_entry.del_type == NDI_MAC_DEL_ALL_ENTRIES){
        nas_mac_event_queue->clear();
        return;
    }
}

static void nas_mac_compact_flush_requests(){
    if(clear_all){
        port_flush_queue->clear();
        vlan_flush_queue->clear();
        port_vlan_flush_queue->clear();
        clear_all = false;
    }

    for(auto it = port_vlan_flush_queue->begin(); it != port_vlan_flush_queue->end() ; ++it){
        if(vlan_flush_queue->find(it->first.vlan_id) == vlan_flush_queue->end() &&
           port_flush_queue->find(it->first.ifindex) == port_flush_queue->end()){
            nas_mac_clear_hw_mac(it->second);
        }
    }

    for(auto it = port_flush_queue->begin(); it != port_flush_queue->end() ; ++it){
        nas_mac_clear_hw_mac(it->second);
    }

    for(auto it = vlan_flush_queue->begin(); it != vlan_flush_queue->end(); ++it){
        nas_mac_clear_hw_mac(it->second);
    }

    for(auto it = bridge_flush_queue->begin(); it != bridge_flush_queue->end(); ++it){
           nas_mac_clear_hw_mac(it->second);
    }

    for(auto it = bridge_endpoint_queue->begin(); it != bridge_endpoint_queue->end(); ++it){
        nas_mac_clear_hw_mac(it->second);
    }

    for(auto it = mac_delete_queue->begin(); it != mac_delete_queue->end(); ++it){
        nas_mac_clear_hw_mac(*it);
    }

    mac_delete_queue->clear();
    port_flush_queue->clear();
    vlan_flush_queue->clear();
    port_vlan_flush_queue->clear();
    bridge_flush_queue->clear();
    bridge_endpoint_queue->clear();


}

static void nas_mac_drain_cps_queue(int fd,size_t count){
    if(nas_mac_read_cps_notification(fd,count,*nas_mac_request_queue)!=STD_ERR_OK){
        return;
    }

    while(!nas_mac_request_queue->empty()){
        nas_mac_cps_event_t & req_entry = nas_mac_request_queue->front();
        switch(req_entry.del_type){
        case NDI_MAC_DEL_BY_PORT:
            port_flush_queue->insert({req_entry.entry.ifindex, std::move(req_entry)});
            break;

        case NDI_MAC_DEL_BY_VLAN:
            vlan_flush_queue->insert({req_entry.entry.entry_key.vlan_id,std::move(req_entry)});
            break;

        case NDI_MAC_DEL_BY_BRIDGE:
            bridge_flush_queue->insert({req_entry.entry.bridge_ifindex,req_entry});
            break;

        case NDI_MAC_DEL_BY_BRIDGE_ENDPOINT_IP:
            bridge_endpoint_queue->insert({{req_entry.entry.endpoint_ip,
                                            req_entry.entry.bridge_ifindex},req_entry});
            break;

        case NDI_MAC_DEL_BY_PORT_VLAN:
        case NDI_MAC_DEL_BY_PORT_VLAN_SUBPORT:
        {
            port_vlan_flush_t pv;
            pv.ifindex=req_entry.entry.ifindex;
            pv.vlan_id=req_entry.entry.entry_key.vlan_id;
            port_vlan_flush_queue->insert({pv, std::move(req_entry)});
        }
            break;

        case NDI_MAC_DEL_ALL_ENTRIES:
            clear_all = true;
            mac_delete_queue->push_back(std::move(req_entry));
            break;

        case NDI_MAC_DEL_SINGLE_ENTRY:
            mac_delete_queue->push_back(std::move(req_entry));
            break;


        default:
            break;
        }
        if(!nas_mac_request_queue->empty()){
            nas_mac_request_queue->pop_front();
        }
    }

    nas_mac_compact_flush_requests();
}


static void nas_mac_process_events(int fd){
    nas_l2_event_header_t ev_hdr;
    t_std_error rc;
    if(std_read(fd,&ev_hdr,sizeof(ev_hdr),true,&rc)!= sizeof(ev_hdr)){
        NAS_MAC_LOG(ERR,"Failed to read mac event header from fd %d",fd);
    }

    if(ev_hdr.ev_type == NAS_MAC_CPS_EVENT){
        nas_mac_drain_cps_queue(fd,ev_hdr.len);
    }

    if(ev_hdr.ev_type == NAS_MAC_NPU_EVENT){
        nas_mac_read_npu_notification(fd,ev_hdr.len,*nas_mac_event_queue);
    }


}

static void nas_mac_process_pending_events(int server_fd){

    if(FD_ISSET(server_fd,&mac_fd_set)){
        if((event_fd[client_count] = accept(server_fd,NULL,NULL)) >= 0){
            if(event_fd[client_count] > max_sock_fd){
                max_sock_fd = event_fd[client_count];
            }

            FD_SET(event_fd[client_count],&mac_master_fd_set);
            client_count++;
            return;
        }
    }

    for(unsigned int i = 0 ; i < client_count ; ++i){
        if(FD_ISSET(event_fd[i],&mac_fd_set)){
            nas_mac_process_events(event_fd[i]);
        }
    }
}


t_std_error nas_mac_connect_to_master_thread(int * client_fd){

    std::unique_lock<std::mutex> _lk(_mtx);
    while(!_server_ready){
        _cv.wait(_lk);
    }

    std_socket_address_t client_sock;
    client_sock.type = e_std_sock_UNIX;
    client_sock.addr_type = e_std_socket_a_t_STRING;
    strncpy(client_sock.address.str,mac_socket_path,sizeof(client_sock.address.str)-1);

    unsigned int attempt_ix = 0;
    while(attempt_ix < nas_mac_max_connect_retries){
        if(std_sock_connect(&client_sock,client_fd) == STD_ERR_OK){
            return STD_ERR_OK;
        }
        attempt_ix++;
        usleep(300);
    }

    EV_LOGGING(L2MAC,ERR,"NAS-MAC-REG","Failed to connect to NAS Master thread");
    return STD_ERR(MAC,FAIL,0);

}


void nas_l2_mac_req_handler(void){

    std_server_socket_desc_t server_socket;
    server_socket.listeners = max_pending_con;
    server_socket.address.addr_type = e_std_socket_a_t_STRING;
    server_socket.address.type = e_std_sock_UNIX;
    strncpy(server_socket.address.address.str,mac_socket_path,sizeof(server_socket.address.address.str)-1);

    {

    std::lock_guard<std::mutex> _lk(_mtx);

    if(std_server_socket_create(&server_socket) != STD_ERR_OK){
        NAS_MAC_LOG(ERR,"Failed to create socket for MAC server thread");
        return;
    }

    _server_ready = true;
    _cv.notify_all();

    }
    max_sock_fd = server_socket.socket;


    FD_ZERO (&mac_fd_set);
    FD_ZERO (&mac_master_fd_set);
    FD_SET (server_socket.socket, &mac_master_fd_set);

    /*
     * Currently use 5m sec as timeout from select, when new mac addresses are being learnt
     * don't send notification, let select timeout and if there are any mac addresses needs
     * to be published, publish it in batches.
     */


    int ret_code;
    t_std_error rc;
    while(1){
        mac_fd_set = mac_master_fd_set;
        struct timeval mac_timeout = {0,5000};

        if((ret_code = std_select_ignore_intr(max_sock_fd+1,&mac_fd_set,NULL,NULL,&mac_timeout,&rc)) >= 0){

            if(ret_code == 0){
                if(nas_mac_event_queue->size() > 0){
                   nas_mac_process_pub_queue();
                }
            }
            else{
                if(nas_mac_event_queue->size() >= max_obj_pub_thresold){
                    nas_mac_process_pub_queue();
                }
                nas_mac_process_pending_events(server_socket.socket);
            }
        }
    }
}


t_std_error nas_mac_send_cps_event_notification(void * data , int len){

    int fd = nas_mac_get_cps_thread_fd();
    t_std_error rc;
    if(std_write(fd,data,len,true,&rc) != len){
        EV_LOGGING(L2MAC,ERR,"L2-FLUSH-NOT","Failed to send event header server");
        return rc;
    }

    return STD_ERR_OK;
}


t_std_error nas_mac_send_npu_event_notification(void * data, int len){
    int fd = nas_mac_get_npu_thread_fd();
    t_std_error rc;
    if(std_write(fd,data,len,true,&rc) != len){
        EV_LOGGING(L2MAC,ERR,"L2-FLUSH-NOT","Failed to send event header server");
        return rc;
    }

    return STD_ERR_OK;
}
