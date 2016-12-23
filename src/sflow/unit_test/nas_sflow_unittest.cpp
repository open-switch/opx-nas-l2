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
 * nas_sflow_unittest.cpp
 *
 */


#include "cps_api_events.h"
#include "cps_api_key.h"
#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "cps_api_errors.h"
#include "gtest/gtest.h"
#include "dell-base-sflow.h"
#include "dell-base-common.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

#include <iostream>
#include <stdlib.h>
#include <map>
#include <string>

static int sflow_id;

using cps_oper = cps_api_return_code_t (*)(cps_api_transaction_params_t * trans,
        cps_api_object_t object);

static std::map<std::string,cps_oper> trans = {
    {"delete",cps_api_delete },
    {"create",cps_api_create},
    {"set",cps_api_set},
};


bool nas_sflow_exec_transaction(std::string op,cps_api_transaction_params_t *tran, cps_api_object_t obj){

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


bool nas_sflow_create_test(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    unsigned int ifindex;
    std::cin>>ifindex;
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_IFINDEX,ifindex);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_DIRECTION,(BASE_CMN_TRAFFIC_PATH_t)BASE_CMN_TRAFFIC_PATH_INGRESS);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_SAMPLING_RATE,1);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        std::cout<<"CPS API CREATE FAILED"<<std::endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ) {
        std::cout<<"CPS API COMMIT FAILED"<<std::endl;
        return false;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);
    cps_api_object_attr_t sflow_id_attr = cps_api_get_key_data(recvd_obj, BASE_SFLOW_ENTRY_ID);
    sflow_id = cps_api_object_attr_data_u32(sflow_id_attr);
    std::cout<<"Recvd SFLOW ID "<<sflow_id<<std::endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API TRANSACTION CLOSED FAILED"<<std::endl;
        return false;
    }

    return true;
}


bool nas_sflow_set_test(){

    cps_api_transaction_params_t tran;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj,BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32,
                         &sflow_id,sizeof(sflow_id));
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_DIRECTION,(BASE_CMN_TRAFFIC_PATH_t)BASE_CMN_TRAFFIC_PATH_EGRESS);
    cps_api_object_attr_add_u32(obj,BASE_SFLOW_ENTRY_SAMPLING_RATE,100);

    if(!nas_sflow_exec_transaction(std::string("set"),&tran,obj)) return false;
    return true;
}


bool nas_sflow_invalid_create_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    if(!nas_sflow_exec_transaction(std::string("create"),&tran,obj)) return false;
    return true;
}


bool nas_sflow_invalid_set_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    if(!nas_sflow_exec_transaction(std::string("set"),&tran,obj)) return false;
    return true;
}


bool nas_sflow_invalid_delete_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    if(!nas_sflow_exec_transaction(std::string("delete"),&tran,obj)) return false;
    return true;
}


bool nas_sflow_delete_test(){

    cps_api_transaction_params_t tran;

    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL ) return false;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32,
                         &sflow_id,sizeof(sflow_id));

    if(!nas_sflow_exec_transaction(std::string("delete"),&tran,obj)) return false;
    return true;
}


bool nas_sflow_get_test(int id){

    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if(obj == NULL){
        std::cout<<"Failed to create and append object to list "<<std::endl;
        return false;
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_SFLOW_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    if(id != -1){
        cps_api_set_key_data(obj,BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32,
                             &sflow_id,sizeof(sflow_id));
    }

    bool rc = false;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0 ; ix < mx ; ++ix ) {
            cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
            cps_api_object_attr_t sflow = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_ID);
            cps_api_object_attr_t ifindex = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_IFINDEX);
            cps_api_object_attr_t rate = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_SAMPLING_RATE);
            cps_api_object_attr_t dir = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_DIRECTION);

            if(sflow != NULL && ifindex != NULL && rate != NULL ){
                std::cout<<"sflow ID "<<cps_api_object_attr_data_u32(sflow)<<std::endl;
                std::cout<<"Ifindex "<<cps_api_object_attr_data_u32(ifindex)<<std::endl;
                std::cout<<"Rate "<<cps_api_object_attr_data_u32(rate)<<std::endl;
                std::cout<<"Direction "<<cps_api_object_attr_data_u32(dir)<<std::endl;
            }

        }
        rc = true;
    }

    cps_api_get_request_close(&gp);
    return rc;
}


TEST(cps_api_events,sflow_test) {
    ASSERT_TRUE(nas_sflow_create_test());
    ASSERT_TRUE(nas_sflow_set_test());

    ASSERT_FALSE(nas_sflow_invalid_create_test());
    ASSERT_FALSE(nas_sflow_invalid_set_test());
    ASSERT_FALSE(nas_sflow_invalid_delete_test());

    ASSERT_TRUE(nas_sflow_get_test(sflow_id));
    ASSERT_TRUE(nas_sflow_get_test(-1));
    ASSERT_TRUE(nas_sflow_delete_test());
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

