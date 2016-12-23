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
 * filename: nas_mac_unittest.cpp
 */

#include "cps_api_events.h"
#include "cps_api_key.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "cps_api_errors.h"
#include "gtest/gtest.h"
#include "dell-base-l2-mac.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

#include <iostream>
#include <stdlib.h>
#include <net/if.h>

#define MAX_MACS 5

using namespace std;
#define STATIC_TYPE false

enum del_filter {
    DEL_MAC = 0x1,
    DEL_VLAN = 0x2,
    DEL_IFINDEX = 0x4,
    DEL_ALL = 0x8
};

typedef struct mac_struct_ {
    hal_mac_addr_t mac_addr;
    hal_vlan_id_t  vlan;
    const char     *if_name;
} mac_struct_t;

mac_struct_t mac_list[MAX_MACS] = { {{0x0, 0xa, 0xb, 0xc, 0xd, 0xe}, 1, "e101-004-0"},
                                    {{0x0, 0xa, 0xb, 0xc, 0xe, 0xe}, 1, "e101-004-0"},

                                    {{0x0, 0xb, 0xc, 0xd, 0xe, 0xf}, 1, "e101-005-0"},
                                    {{0x0, 0xb, 0xc, 0xd, 0xd, 0xf}, 1, "e101-014-0"},

                                    {{0x0, 0xc, 0xd, 0xe, 0xf, 0xa}, 1, "e101-005-0"}};

bool nas_mac_test_3(){

    hal_vlan_id_t  vlan_id;
    int i;
    cout<<"Entered nas_mac_test_3"<<endl;
    cout<<"========================"<<endl;
    for (i = 0; i < MAX_MACS; i ++) {
        cps_api_transaction_params_t tran;
        if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

        cps_api_key_t key;
        cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET);

        cps_api_object_t obj = cps_api_object_create();

        if(obj == NULL )
            return false;

        cps_api_object_set_key(obj,&key);
        cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS, mac_list[i].mac_addr, sizeof(hal_mac_addr_t));
        cps_api_object_attr_add_u16(obj,BASE_MAC_TABLE_VLAN,mac_list[i].vlan);

        int index = if_nametoindex(mac_list[i].if_name);
        cout<<" If index in test_2 is "<<index<<endl;
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX, index);
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_CONFIGURE_OS, index);

        if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
            cout<<"CPS API CREATE FAILED"<<endl;
            return false;
        }

        if(cps_api_commit(&tran) != cps_api_ret_code_OK ) {
            cout<<"CPS API COMMIT FAILED"<<endl;
            return false;
        }
        else {
            cout<<"CPS API COMMIT PASSED"<<endl;
        }

        cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);

        cps_api_object_attr_t vlan_attr = cps_api_get_key_data(recvd_obj, BASE_MAC_TABLE_VLAN);
        vlan_id = cps_api_object_attr_data_u16(vlan_attr);

        cout<<"VLAN Id from create "<<vlan_id<<endl;

        if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
            cout<<"CPS API TRANSACTION CLOSED"<<endl;
            return false;
        }

        cout<<"CPS API TRANSACTION CLOSED : SUCCEED"<<endl;
    } // for loop
    return true;
}


bool nas_mac_test_2(int vlan, int index){

    hal_vlan_id_t  vlan_id;
    hal_mac_addr_t mac_addr;

    cps_api_transaction_params_t tran;
    cout<<"Entered nas_mac_test_2"<<endl;
    cout<<"========================"<<endl;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL )
        return false;

    cps_api_object_set_key(obj,&key);
    mac_addr[0] = 0xd;
    mac_addr[1] = 0xe;
    mac_addr[2] = 0xf;
    mac_addr[3] = 0xa;
    mac_addr[4] = 0xd;
    mac_addr[5] = 0xb;
    cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS, mac_addr, sizeof(hal_mac_addr_t));
    cps_api_object_attr_add_u16(obj,BASE_MAC_TABLE_VLAN,vlan);

    cout<<" If index in test_2 is "<<index<<endl;
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX, index);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API CREATE FAILED"<<endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ) {
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }
    else {
        cout<<"CPS API COMMIT PASSED"<<endl;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);

    cps_api_object_attr_t vlan_attr = cps_api_get_key_data(recvd_obj, BASE_MAC_TABLE_VLAN);
    vlan_id = cps_api_object_attr_data_u16(vlan_attr);

    cout<<"VLAN Id from create "<<vlan_id<<endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API TRANSACTION CLOSED"<<endl;
        return false;
    }

    cout<<"CPS API TRANSACTION CLOSED : SUCCEED"<<endl;
    return true;
}

bool nas_mac_test(){

    hal_vlan_id_t  vlan_id;
    hal_mac_addr_t mac_addr;

    cps_api_transaction_params_t tran;
    cout<<"Entered nas_mac_test"<<endl;
    cout<<"========================"<<endl;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL )
        return false;

    cps_api_object_set_key(obj,&key);
    mac_addr[0] = 0xa;
    mac_addr[1] = 0xb;
    mac_addr[2] = 0xc;
    mac_addr[3] = 0xd;
    mac_addr[4] = 0xe;
    mac_addr[5] = 0xf;

    cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS, mac_addr, sizeof(hal_mac_addr_t));
    cps_api_object_attr_add_u16(obj,BASE_MAC_TABLE_VLAN,200);

    const char *if_name = "e00-4";
    int index = if_nametoindex(if_name);
    cout<<" If index in test is "<<index<<endl;
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX, index);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API CREATE FAILED"<<endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ) {
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }
    else {
        cout<<"CPS API COMMIT PASSED"<<endl;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);

    cps_api_object_attr_t vlan_attr = cps_api_get_key_data(recvd_obj, BASE_MAC_TABLE_VLAN);
    vlan_id = cps_api_object_attr_data_u16(vlan_attr);

    cout<<"VLAN Id from create "<<vlan_id<<endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API TRANSACTION CLOSED"<<endl;
        return false;
    }

    cout<<"CPS API TRANSACTION CLOSED : SUCCEED"<<endl;
    return true;
}

bool nas_mac_add_entry(){

    cps_api_transaction_params_t tran;
    hal_mac_addr_t mac_addr;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if (obj == NULL)
        return false;

    cps_api_object_set_key(obj,&key);

    mac_addr[0] = 'a';
    mac_addr[1] = 'c';
    mac_addr[2] = 'e';
    mac_addr[3] = 'b';
    mac_addr[4] = 'd';
    mac_addr[5] = 'f';

    const char *if_name = "e00-8";
    int index = if_nametoindex(if_name);
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_IFINDEX, index);
    cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_VLAN, 400);
    cps_api_object_attr_add(obj,BASE_MAC_TABLE_MAC_ADDRESS, mac_addr, sizeof(hal_mac_addr_t));

    if(cps_api_set(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API SET FAILED"<<endl;
        return false;
    }

    cout<<"CPS API SET PASSED"<<endl;

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }

    cout<<"CPS API COMMIT PASSED"<<endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API TRANSACTION CLOSED"<<endl;
        return false;
    }

    cout<<"CPS API TRANSACTION CLOSED : SUCCEED"<<endl;

    return true;
}

bool nas_mac_delete(int array_index, int del_filter, bool static_type){

    cps_api_transaction_params_t tran;

    cout<<"Entered nas_mac_delete"<<endl;
    cout<<"========================"<<endl;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_TABLE_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL )
        return false;

    cps_api_object_set_key(obj,&key);
    if (del_filter & DEL_MAC) {
        cps_api_object_attr_add(obj,BASE_MAC_QUERY_MAC_ADDRESS,
                                mac_list[array_index].mac_addr, sizeof(hal_mac_addr_t));
    }
    if (del_filter & DEL_VLAN) {
        cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_VLAN, mac_list[array_index].vlan);
    }
    if (del_filter & DEL_IFINDEX) {
        int index = if_nametoindex(mac_list[array_index].if_name);
        cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_IFINDEX, index);
    }
    else if (del_filter & DEL_ALL) {
        // set no flags ?
    }
    if (static_type) {
        cps_api_object_attr_add_u32(obj,BASE_MAC_TABLE_STATIC, static_type);
    }

    if(cps_api_delete(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API DELETE FAILED"<<endl;
        return false;
    }

    cout<<"CPS API DELETE PASSED"<<endl;

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }

    cout<<"CPS API COMMIT PASSED"<<endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API TRANSACTION CLOSED"<<endl;
        return false;
    }

    cout<<"CPS API TRANSACTION CLOSED : SUCCEED"<<endl;

    return true;
}

bool nas_mac_flush_test(bool vlan,bool ifindex){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_FLUSH_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL)
        return false;

    cps_api_object_set_key(obj,&key);
    cps_api_attr_id_t ids[3] = {BASE_MAC_FLUSH_INPUT_FILTER,0, BASE_MAC_FLUSH_INPUT_FILTER_VLAN };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    if (vlan) {
        uint16_t vlan_list[3]={1,2,3};
        for(unsigned int ix=0;
            ix<sizeof(vlan_list)/sizeof(vlan_list[0]);
            ++ix){
            ids[1]=ix;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U16,&(vlan_list[ix]),sizeof(vlan_list[ix]));
        }
    }

    if (ifindex) {
        int ifidx;
        ids[2]=BASE_MAC_FLUSH_INPUT_FILTER_IFINDEX;
        for(unsigned int ix=0; ix<3; ++ix){
            ids[1]=ix;
            std::cout<<"Enter the ifindex"<<std::endl;
            std::cin>>ifidx;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U16,&(ifidx),sizeof(ifidx));
        }
    }


    if(cps_api_action(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API RPC FAILED"<<endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        cout<<"CPS API TRANSACTION CLOSED"<<endl;
        return false;
    }

    return true;
}

bool nas_mac_get_test(bool static_type){

    cps_api_get_params_t gp;
    cout<<"Entered nas_mac_get_test"<<endl;
    cout<<"========================"<<endl;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;

    cps_api_key_from_attr_with_qual(&key, BASE_MAC_QUERY_OBJ, cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);
    cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_STATIC, static_type);

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        cout<<"Returned Objects..."<<mx<<endl;
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t vlan_id = cps_api_object_attr_get(obj,BASE_MAC_QUERY_VLAN);
            cps_api_object_attr_t ifindex = cps_api_object_attr_get(obj,BASE_MAC_QUERY_IFINDEX);
            cps_api_object_attr_t mac_addr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_MAC_ADDRESS);
            cout<< " "<<endl;
            cout<<"VLAN ID "<<cps_api_object_attr_data_u16(vlan_id)<<endl;
            cout<<"IFINDEX "<<cps_api_object_attr_data_u32(ifindex)<<endl;
            char mt[6];
            char mstring[20];
            memcpy(mt, cps_api_object_attr_data_bin(mac_addr), 6);
            sprintf(mstring, "%x:%x:%x:%x:%x:%x", mt[0], mt[1], mt[2], mt[3], mt[4], mt[5]);
            cout<<"MAC              "<<mstring<<endl;
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}
bool nas_mac_get_by_vlan_test() {

    cps_api_get_params_t gp;
    cout<<"Entered nas_mac_get_by_vlan_test"<<endl;
    cout<<"========================"<<endl;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;

    cps_api_key_from_attr_with_qual(&key,BASE_MAC_QUERY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_VLAN, 100);
    cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_STATIC, 1);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_REQUEST_TYPE, BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_VLAN);

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        cout<<"VLAN BASED QUERY *********** Returned Objects..."<<mx<<endl;
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t vlan_id = cps_api_object_attr_get(obj,BASE_MAC_QUERY_VLAN);
            cps_api_object_attr_t ifindex = cps_api_object_attr_get(obj,BASE_MAC_QUERY_IFINDEX);
            cps_api_object_attr_t mac_addr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_MAC_ADDRESS);
            cout<<"VLAN ID **********"<<cps_api_object_attr_data_u16(vlan_id)<<endl;
            cout<<"IFINDEX **********"<<cps_api_object_attr_data_u32(ifindex)<<endl;
            char mt[6];
            char mstring[20];
            memcpy(mt, cps_api_object_attr_data_bin(mac_addr), 6);
            sprintf(mstring, "%x:%x:%x:%x:%x:%x", mt[0], mt[1], mt[2], mt[3], mt[4], mt[5]);
            cout<<"MAC              "<<mstring<<endl;
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}

bool nas_mac_get_by_mac_test(int array_index) {

    cps_api_get_params_t gp;
    cout<<"Entered nas_mac_get_by_mac_test"<<endl;
    cout<<"========================"<<endl;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;

    cps_api_key_from_attr_with_qual(&key,BASE_MAC_QUERY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add(obj,BASE_MAC_QUERY_MAC_ADDRESS, mac_list[array_index].mac_addr, sizeof(hal_mac_addr_t));
    cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_STATIC, 1);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_REQUEST_TYPE, BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_ADDRESS);

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        cout<<"MAC BASED QUERY *********** Returned Objects..."<<mx<<endl;
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t vlan_id = cps_api_object_attr_get(obj,BASE_MAC_QUERY_VLAN);
            cps_api_object_attr_t ifindex = cps_api_object_attr_get(obj,BASE_MAC_QUERY_IFINDEX);
            cps_api_object_attr_t mac_addr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_MAC_ADDRESS);
            cout<<"VLAN ID **********"<<cps_api_object_attr_data_u16(vlan_id)<<endl;
            cout<<"IFINDEX **********"<<cps_api_object_attr_data_u32(ifindex)<<endl;
            char mt[6];
            char mstring[20];
            memcpy(mt, cps_api_object_attr_data_bin(mac_addr), 6);
            sprintf(mstring, "%x:%x:%x:%x:%x:%x", mt[0], mt[1], mt[2], mt[3], mt[4], mt[5]);
            cout<<"MAC              "<<mstring<<endl;
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}
bool nas_mac_get_count_test(int vlan, int if_index, bool static_type) {
    cps_api_get_params_t gp;
    cout<<"Entered nas_mac_get_count_test"<<endl;
    cout<<"========================"<<endl;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cout<<"MAC Count : ********** querying vlan "<< vlan << " : if_index "<< if_index<<endl;
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MAC_QUERY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    if (vlan) {
        cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_VLAN, vlan);
    }
    if (if_index) {
        cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_IFINDEX, if_index);
    }

    if (static_type) {
        cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_STATIC, 1);
    }
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_REQUEST_TYPE, BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_COUNT);
    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t mac_count = cps_api_object_attr_get(obj,BASE_MAC_QUERY_COUNT);
            cout<<"MAC Count : **********"<<cps_api_object_attr_data_u32(mac_count)<<endl;
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}

bool nas_mac_get_by_if_test() {

    cps_api_get_params_t gp;
    cout<<"Entered nas_mac_get_by_it_test"<<endl;
    cout<<"========================"<<endl;
    cps_api_get_request_init(&gp);
    const char *if_name = "e00-4";
    int index = if_nametoindex(if_name);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;

    cps_api_key_from_attr_with_qual(&key,BASE_MAC_QUERY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_IFINDEX, index);
    cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_STATIC, 1);
    cps_api_object_attr_add_u32(obj,BASE_MAC_QUERY_REQUEST_TYPE, BASE_MAC_COMMAND_REQUEST_TYPE_CMD_TYPE_INTERFACE);

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        cout<<"IF BASED QUERY *********** Returned Objects..."<<mx<<endl;
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t vlan_id = cps_api_object_attr_get(obj,BASE_MAC_QUERY_VLAN);
            cps_api_object_attr_t ifindex = cps_api_object_attr_get(obj,BASE_MAC_QUERY_IFINDEX);
            cps_api_object_attr_t mac_addr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_MAC_ADDRESS);
            cout<<"VLAN ID **********"<<cps_api_object_attr_data_u16(vlan_id)<<endl;
            cout<<"IFINDEX **********"<<cps_api_object_attr_data_u32(ifindex)<<endl;
            char mt[6];
            char mstring[20];
            memcpy(mt, cps_api_object_attr_data_bin(mac_addr), 6);
            sprintf(mstring, "%x:%x:%x:%x:%x:%x", mt[0], mt[1], mt[2], mt[3], mt[4], mt[5]);
            cout<<"MAC              "<<mstring<<endl;
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}

bool nas_mac_auto_flush_management(bool enable){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_MAC_FLUSH_MANAGEMENT_OBJ, cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL )
        return false;

    cps_api_object_set_key(obj,&key);
    cps_api_object_attr_add_u32(obj,BASE_MAC_FLUSH_MANAGEMENT_ENABLE,enable);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        cout<<"CPS API CREATE FAILED"<<endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ) {
        cout<<"CPS API COMMIT FAILED"<<endl;
        return false;
    }else{
        cout<<"CPS API COMMIT PASSED"<<endl;
    }

     cps_api_get_params_t gp;
     cps_api_get_request_init(&gp);
     cps_api_key_t key1;
     cps_api_key_from_attr_with_qual(&key1,BASE_MAC_FLUSH_MANAGEMENT_OBJ,cps_api_qualifier_TARGET);
     gp.key_count = 1;
     gp.keys = &key1;

     bool rc = false;
     if (cps_api_get(&gp)==cps_api_ret_code_OK) {
         size_t mx = cps_api_object_list_size(gp.list);
         for (size_t ix = 0 ; ix < mx ; ++ix ) {
             cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
             cps_api_object_attr_t auto_mgmt = cps_api_object_attr_get(obj,BASE_MAC_FLUSH_MANAGEMENT_ENABLE);
             if(auto_mgmt){
                 cout<<"Auto MAC Management Value : "<<cps_api_object_attr_data_u32(auto_mgmt)<<endl;
             }

         }
         rc = true;
     }

    cps_api_get_request_close(&gp);
    return rc;
}


TEST(cps_api_events,mac_test) {

    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_by_vlan_test());
    ASSERT_TRUE(nas_mac_get_by_mac_test(1)); // pass the index into mac_list
    ASSERT_TRUE(nas_mac_get_by_if_test());
    ASSERT_TRUE(nas_mac_get_count_test(0, 0, true));
    ASSERT_TRUE(nas_mac_get_count_test(100, 18, true));
    ASSERT_TRUE(nas_mac_get_count_test(100, 0, STATIC_TYPE));
    ASSERT_TRUE(nas_mac_get_count_test(200, 0, true));
    ASSERT_TRUE(nas_mac_get_count_test(0, 16, true));
    ASSERT_TRUE(nas_mac_get_count_test(201 , 16, true));
    ASSERT_TRUE(nas_mac_get_count_test(201 , 0, true));
    ASSERT_TRUE(nas_mac_get_count_test(0 , 18, true));
    ASSERT_TRUE(nas_mac_get_count_test(0 , 18, false));
    ASSERT_TRUE(nas_mac_get_test(true));
    cout<<"DEL_IFINDEX "<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(STATIC_TYPE));
    ASSERT_TRUE(nas_mac_delete(3, DEL_IFINDEX, STATIC_TYPE));
    ASSERT_TRUE(nas_mac_get_test(STATIC_TYPE));


    cout<<"DEL_VLAN"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(STATIC_TYPE));
    ASSERT_TRUE(nas_mac_delete(3, DEL_VLAN , STATIC_TYPE));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"DEL_MAC"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_MAC , true));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"DEL_IFINDEX | VLAN"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_IFINDEX | DEL_VLAN , STATIC_TYPE));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"DEL_IFINDEX | MAC"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_IFINDEX | DEL_MAC , true));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"DEL_VLAN | MAC"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_VLAN | DEL_MAC , true));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"DEL_VLAN | MAC"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_VLAN | DEL_MAC|DEL_IFINDEX , true));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"FLUSH ALL"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_ALL , true));
    ASSERT_TRUE(nas_mac_delete(3, DEL_ALL , false));
    ASSERT_TRUE(nas_mac_get_test(true));

    cout<<"CREATE"<<endl;
    ASSERT_TRUE(nas_mac_test_3());
    ASSERT_TRUE(nas_mac_get_test(false));

    cout<<"FLUSH LIST"<<endl;
    ASSERT_TRUE(nas_mac_flush_test(true,false));
    ASSERT_TRUE(nas_mac_flush_test(false,true));
    ASSERT_TRUE(nas_mac_flush_test(true,true));

    cout<<"AUTO FLUSH"<<endl;
    ASSERT_TRUE(nas_mac_auto_flush_management(false));
    ASSERT_TRUE(nas_mac_auto_flush_management(true));

}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
