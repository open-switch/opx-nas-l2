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
 * filename: nas_stg_unittest.cpp
 */

#include "cps_api_events.h"
#include "cps_api_key.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "cps_api_errors.h"
#include "gtest/gtest.h"
#include "dell-base-stg.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "iana-if-type.h"

#include <iostream>
#include <stdlib.h>
#include <map>
#include <string>

static unsigned int stg_id=0;
static unsigned int default_stg_id;


using cps_oper = cps_api_return_code_t (*)(cps_api_transaction_params_t * trans,
        cps_api_object_t object);

static std::map<std::string,cps_oper> trans = {
    {"delete",cps_api_delete },
    {"create",cps_api_create},
    {"set",cps_api_set},
};


bool nas_stg_exec_transaction(std::string op,cps_api_transaction_params_t *tran, cps_api_object_t obj){

    if(trans[op](tran,obj) != cps_api_ret_code_OK ){
         std::cout<<"cps api" + op +"failed"<<std::endl;
         return false;
    }

    if(cps_api_commit(tran) != cps_api_ret_code_OK ){
        std::cout<<"cps api commit failed"<<std::endl;
        return false;
    }

    if(cps_api_transaction_close(tran) != cps_api_ret_code_OK ){
        std::cout<<"cps api transaction close failed"<<std::endl;
        return false;
    }

    return true;
}

bool nas_vlan_create(unsigned int vlan_id){

      cps_api_object_t obj = cps_api_object_create();

      cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                      DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                      cps_api_qualifier_TARGET);

      cps_api_object_attr_add(obj,IF_INTERFACES_INTERFACE_TYPE,
           (const char *)IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_L2VLAN,
           sizeof(IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_L2VLAN));

      cps_api_object_attr_add_u32(obj,BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID,vlan_id);

      cps_api_transaction_params_t tr;
      if ( cps_api_transaction_init(&tr) != cps_api_ret_code_OK ) return false;
      if(!nas_stg_exec_transaction(std::string("create"),&tr,obj)) return false;
      return true;
}

bool nas_stg_ut_init(){
    for (size_t ix = 2 ; ix < 8 ; ++ix){
        if(!nas_vlan_create(ix)) return false;
    }
    return true;
}

bool nas_stg_add_vlan_test(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_VLAN,cps_api_qualifier_TARGET);
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                                     &stg_id,sizeof(stg_id));

    uint32_t vid[] = {6,7};
    for(size_t ix = 0 ; ix < sizeof(vid)/sizeof(vid[0]) ; ++ix ){
        cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,vid[ix]);
    }


    if(!nas_stg_exec_transaction(std::string("create"),&tran,obj)) return false;

    return true;

}


bool nas_stg_del_vlan_test(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_VLAN,cps_api_qualifier_TARGET);
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                                     &stg_id,sizeof(stg_id));

    uint32_t vid[] = {4};
    for(size_t ix = 0 ; ix < sizeof(vid)/sizeof(vid[0]) ; ++ix ){
        cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,vid[ix]);
    }


    if(!nas_stg_exec_transaction(std::string("delete"),&tran,obj)) return false;

    return true;

}


bool nas_stg_create_test(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);

    uint32_t vid[]= {2,3,4,5};
    for(size_t ix = 0 ; ix < sizeof(vid)/sizeof(vid[0]) ; ++ix ){
        cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,vid[ix]);
    }

    cps_api_attr_id_t ids[3] = {BASE_STG_ENTRY_INTF, 0,BASE_STG_ENTRY_INTF_STATE };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    BASE_STG_INTERFACE_STATE_t stp_state =BASE_STG_INTERFACE_STATE_LEARNING;

    hal_ifindex_t ifindex ;
    std::cout<<"Enter the ifindex"<<std::endl;
    std::cin>>ifindex;

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&stp_state,sizeof(stp_state));
    ids[2]= BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,sizeof(ifindex));

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
         std::cout<<"cps api create failed"<<std::endl;
         return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        std::cout<<"cps api commit failed"<<std::endl;
        return false;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);
    cps_api_object_attr_t stg_id_attr = cps_api_get_key_data(recvd_obj, BASE_STG_ENTRY_ID);
    stg_id = cps_api_object_attr_data_u32(stg_id_attr);
    std::cout<<"STG Id from create "<<stg_id<<std::endl;


    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        std::cout<<"cps api transaction close failed"<<std::endl;
        return false;
    }

    return true;
}

bool nas_stg_update_test(){

    cps_api_transaction_params_t tran;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                                 &stg_id,sizeof(stg_id));

    uint32_t vid[] = {3,4};
    for(size_t ix = 0 ; ix < sizeof(vid)/sizeof(vid[0]) ; ++ix ){
        cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,vid[ix]);
    }

    cps_api_attr_id_t ids[3] = {BASE_STG_ENTRY_INTF, 0,BASE_STG_ENTRY_INTF_STATE };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    BASE_STG_INTERFACE_STATE_t stp_state =(BASE_STG_INTERFACE_STATE_t)BASE_STG_INTERFACE_STATE_LISTENING;

    std::cout<<"Please Enter ifindex for updating stp state"<<std::endl;
    hal_ifindex_t ifindex;
    std::cin>>ifindex;

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&stp_state,sizeof(stp_state));
    ids[2]= BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,sizeof(ifindex));

    if(!nas_stg_exec_transaction(std::string("set"),&tran,obj)) return false;

    return true;
}


bool nas_stg_invalid_set_test(){

    cps_api_transaction_params_t tran;

   if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

   cps_api_key_t key;
   cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

   cps_api_object_t obj = cps_api_object_create();

   if(obj == NULL ) return false;
   cps_api_object_set_key(obj,&key);

   if(!nas_stg_exec_transaction(std::string("set"),&tran,obj)) return false;
   return true;
}


bool nas_stg_invalid_del_test(){

    cps_api_transaction_params_t tran;

   if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

   cps_api_key_t key;
   cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

   cps_api_object_t obj = cps_api_object_create();

   if(obj == NULL ) return false;
   cps_api_object_set_key(obj,&key);

   if(!nas_stg_exec_transaction(std::string("delete"),&tran,obj)) return false;

   return true;
}


bool nas_stg_bulk_set_test(){

    cps_api_transaction_params_t tran;

   if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

   cps_api_key_t key;
   cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

   cps_api_object_t obj = cps_api_object_create();

   if(obj == NULL ) return false;
   cps_api_object_set_key(obj,&key);

   for(size_t ix = 1 ; ix < 500 ; ++ix ){
       cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,ix);
   }

   if(!nas_stg_exec_transaction(std::string("create"),&tran,obj)) return false;
   return true;
}

void nas_stg_dump_object_content(cps_api_object_t obj){
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);
    cps_api_attr_id_t ids[2] = {BASE_STG_ENTRY_INTF, BASE_STG_ENTRY_INTF_STATE };
    cps_api_object_attr_t stp_state_attr,ifindex_attr;
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {

        case BASE_STG_ENTRY_VLAN:
            std::cout<<"VLAN ID "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_STG_DEFAULT_STG_ID:
            default_stg_id = cps_api_object_attr_data_u32(it.attr);
            std::cout<<"Default STG Id "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_STG_ENTRY_ID:
            std::cout<<"STG ID "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_STG_ENTRY_INTF:

            stp_state_attr = cps_api_object_e_get(obj,ids,ids_len);
            ids[1] = BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
            ifindex_attr = cps_api_object_e_get(obj,ids,ids_len);
            std::cout<<"IFINDEX "<<cps_api_object_attr_data_u32(ifindex_attr)<<std::endl;
            std::cout<<"STP STATE "<<cps_api_object_attr_data_u32(stp_state_attr)<<std::endl;
            break;

        default:
            break;
        }
    }
}


bool nas_stg_get_instance_test(){

    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);

    if (obj == NULL) {
      std::cout<<"Can not create new object"<<std::endl;
      return false;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                                 &stg_id,sizeof(stg_id));

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
             cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
             nas_stg_dump_object_content(obj);
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}


bool nas_stg_get_all_test(){
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    bool rc = false;
    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            nas_stg_dump_object_content(obj);
        }
        rc = true;
    }
    cps_api_get_request_close(&gp);
    return rc;
}

bool nas_stg_get_default_test(){
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    gp.key_count = 0;
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }
    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    int nas_stg_id = 0;
    cps_api_set_key_data(obj,BASE_STG_DEFAULT_STG_ID,cps_api_object_ATTR_T_U32,
                                         &nas_stg_id,sizeof(nas_stg_id));

    bool rc = false;
    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            nas_stg_dump_object_content(obj);
        }
        rc = true;
    }
    cps_api_get_request_close(&gp);
    return rc;
}


bool nas_stg_del_test(){

    cps_api_transaction_params_t tran;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                                 &stg_id,sizeof(stg_id));

    if(!nas_stg_exec_transaction(std::string("delete"),&tran,obj)) return false;
    return true;
}

bool nas_stg_update_default_test(){

    cps_api_transaction_params_t tran;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_STG_ENTRY_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();

    if(obj == NULL ) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_STG_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &default_stg_id,sizeof(default_stg_id));

    uint32_t vid[] = {3,4};
    for(size_t ix = 0 ; ix < sizeof(vid)/sizeof(vid[0]) ; ++ix ){
        cps_api_object_attr_add_u32(obj,BASE_STG_ENTRY_VLAN,vid[ix]);
    }

    cps_api_attr_id_t ids[3] = {BASE_STG_ENTRY_INTF, 0,BASE_STG_ENTRY_INTF_STATE };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    BASE_STG_INTERFACE_STATE_t stp_state =(BASE_STG_INTERFACE_STATE_t)BASE_STG_INTERFACE_STATE_LEARNING;

    std::cout<<"Please Enter ifindex for updating stp state"<<std::endl;
    hal_ifindex_t ifindex;
    std::cin>>ifindex;

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&stp_state,sizeof(stp_state));
    ids[2]= BASE_STG_ENTRY_INTF_IF_INDEX_IFINDEX;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&ifindex,sizeof(ifindex));

    if(!nas_stg_exec_transaction(std::string("set"),&tran,obj)) return false;

    return true;
}



TEST(cps_api_events,stg_test) {

    ASSERT_TRUE(nas_stg_ut_init());
    ASSERT_TRUE(nas_stg_get_default_test());
    ASSERT_TRUE(nas_stg_update_default_test());

    ASSERT_TRUE(nas_stg_create_test());
    ASSERT_TRUE(nas_stg_update_test());
    ASSERT_TRUE(nas_stg_add_vlan_test());
    ASSERT_TRUE(nas_stg_del_vlan_test());

    ASSERT_FALSE(nas_stg_invalid_set_test());
    ASSERT_FALSE(nas_stg_invalid_del_test());

    //ASSERT_TRUE(nas_stg_bulk_set_test());

    ASSERT_TRUE(nas_stg_get_instance_test());
    ASSERT_TRUE(nas_stg_get_all_test());

    ASSERT_TRUE(nas_stg_del_test());
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
