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
 * filename: nas_mirror_unittest.cpp
 */


#include "cps_api_key.h"
#include "cps_api_operation.h"
#include "gtest/gtest.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "nas_ndi_obj_id_table.h"
#include "dell-base-mirror.h"
#include "dell-base-common.h"

#include <iostream>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <map>
#include <net/if.h>

static unsigned int mirror_id;
static unsigned int rspan_mirror_id;
static unsigned int erspan_mirror_id;


using cps_oper = cps_api_return_code_t (*)(cps_api_transaction_params_t * trans,
        cps_api_object_t object);


static std::map<std::string,cps_oper> trans = {
    {"delete",cps_api_delete },
    {"create",cps_api_create},
    {"set",cps_api_set},
};


bool nas_mirror_exec_transaction(std::string op,cps_api_transaction_params_t *tran, cps_api_object_t obj){

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


bool nas_mirror_add_same_source_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                           cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);

    unsigned int src_intf = if_nametoindex("e101-001-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-002-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TYPE,BASE_MIRROR_MODE_SPAN);

    if(!nas_mirror_exec_transaction(std::string("create"),&tran,obj)) return false;

    return true;
}


bool nas_mirror_set_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;

    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                             &mirror_id,sizeof(mirror_id));

    unsigned int src_intf = if_nametoindex("e101-004-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-005-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));

    if(!nas_mirror_exec_transaction(std::string("set"),&tran,obj)) return false;

    return true;

}


bool nas_mirror_del_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &mirror_id,sizeof(mirror_id));

    if(!nas_mirror_exec_transaction(std::string("delete"),&tran,obj)) return false;

    return true;
}

void nas_mirror_dump_object_content(cps_api_object_t obj){
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch (cps_api_object_attr_id(it.attr)) {

        case BASE_MIRROR_ENTRY_TYPE:
            std::cout<<"Mirror Type "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_MIRROR_ENTRY_ID:
            std::cout<<"Id "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            std::cout<<"Mirror Id Len "<<cps_api_object_attr_len(it.attr)<<std::endl;
            break;

        case BASE_MIRROR_ENTRY_DST_INTF:
            std::cout<<"Dest intf "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_MIRROR_ENTRY_OPAQUE_DATA:
        {
            nas::ndi_obj_id_table_t mirror_opaque_data_table;
            cps_api_attr_id_t  attr_id_list[] = {BASE_MIRROR_ENTRY_OPAQUE_DATA};
            nas::ndi_obj_id_table_cps_unserialize (mirror_opaque_data_table, obj, attr_id_list,
                                                   sizeof(attr_id_list)/sizeof(attr_id_list[0]));
            auto it = mirror_opaque_data_table.begin();
            std::cout<<" NPU ID "<<it->first<<std::endl;
            std::cout<<" SAI MIRROR ID"<<it->second<<std::endl;
        }
            break;

        default:
            break;
        }
    }
}


bool nas_mirror_add_test(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                        cps_api_qualifier_TARGET);
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);

    unsigned int src_intf = if_nametoindex("e101-001-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-002-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));


    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TYPE,BASE_MIRROR_MODE_SPAN);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        std::cout<<"CPS API CREATE FAILED"<<std::endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API COMMIT FAILED"<<std::endl;
        return false;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);

    std::cout <<" Printing Returned Object "<<std::endl;

    nas_mirror_dump_object_content(recvd_obj);

    cps_api_object_attr_t mirror_id_attr = cps_api_get_key_data(recvd_obj, BASE_MIRROR_ENTRY_ID);
    mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);
    std::cout<<"Mirror Id from create "<<mirror_id<<std::endl;
    std::cout<<"Mirror Id Len "<<cps_api_object_attr_len(mirror_id_attr)<<std::endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API TRANSACTION CLOSED"<<std::endl;
        return false;
    }

    return true;
}

bool nas_mirror_get_test(){

    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_key_t key;

    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                        cps_api_qualifier_TARGET);
    gp.key_count = 1;
    gp.keys = &key;

    bool rc = false;

    cps_api_object_t obj;
    if (cps_api_get(&gp)==cps_api_ret_code_OK) {

        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {

            obj = cps_api_object_list_get(gp.list,ix);
            nas_mirror_dump_object_content(obj);
        }
        rc = true;
    }

    cps_api_get_request_close(&gp);

    return rc;
}


bool nas_mirror_rspan_create(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);

    unsigned int src_intf = if_nametoindex("e101-006-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-008-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);


    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));
    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));

    src_intf = if_nametoindex("e101-007-0");
    dir = BASE_CMN_TRAFFIC_PATH_EGRESS;
    ids[1] = 1;
    ids[2] = BASE_MIRROR_ENTRY_INTF_SRC;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));
    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));


    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TYPE,BASE_MIRROR_MODE_RSPAN);
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_VLAN,5);

    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        std::cout<<"CPS API CREATE FAILED"<<std::endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API COMMIT FAILED"<<std::endl;
        return false;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);
    cps_api_object_attr_t mirror_id_attr = cps_api_get_key_data(recvd_obj, BASE_MIRROR_ENTRY_ID);
    rspan_mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);
    std::cout<<"RSPAN Mirror Id from create "<<rspan_mirror_id<<std::endl;

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API TRANSACTION CLOSED"<<std::endl;
        return false;
    }

    return true;
}

bool nas_mirror_rspan_set(){

    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                       cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;

    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &rspan_mirror_id,sizeof(rspan_mirror_id));


    unsigned int src_intf = if_nametoindex("e101-001-00");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,20);

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));

    src_intf = if_nametoindex("e101-001-0");
    ids[1]= 1;
    ids[2]=BASE_MIRROR_ENTRY_INTF_SRC;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));

    if(!nas_mirror_exec_transaction(std::string("set"),&tran,obj)) return false;

    return true;

}


bool nas_mirror_erspan_create(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);

    unsigned int src_intf = if_nametoindex("e101-001-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-002-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));


    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TYPE,BASE_MIRROR_MODE_ERSPAN);
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_ERSPAN_VLAN_ID,1);
    //1.1.2.2
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DESTINATION_IP,16843266);
    // 1.1.3.1
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_SOURCE_IP,16843521);
    uint8_t src_mac[]={0x90,0xb1,0x1c,0xf4,0x9c,0x57};
    uint8_t dst_mac[]={0x90,0xb1,0x1c,0xf4,0x9c,0x5b};
    cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_DEST_MAC,(void*)dst_mac,6);
    cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_SOURCE_MAC,(void *)src_mac,6);
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_TTL,200);
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DSCP,5);
    cps_api_object_attr_add_u16(obj,BASE_MIRROR_ENTRY_GRE_PROTOCOL_TYPE,8894);


    if(cps_api_create(&tran,obj) != cps_api_ret_code_OK ){
        std::cout<<"CPS API CREATE FAILED"<<std::endl;
        return false;
    }

    if(cps_api_commit(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API COMMIT FAILED"<<std::endl;
        return false;
    }

    cps_api_object_t recvd_obj = cps_api_object_list_get(tran.change_list,0);
    cps_api_object_attr_t mirror_id_attr = cps_api_get_key_data(recvd_obj, BASE_MIRROR_ENTRY_ID);
    erspan_mirror_id = cps_api_object_attr_data_u32(mirror_id_attr);

    if(cps_api_transaction_close(&tran) != cps_api_ret_code_OK ){
        std::cout<<"CPS API TRANSACTION CLOSED"<<std::endl;
        return false;
    }

    return true;
}


bool nas_mirror_erspan_set(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &erspan_mirror_id,sizeof(erspan_mirror_id));

    unsigned int src_intf = if_nametoindex("e101-008-0");
    BASE_CMN_TRAFFIC_PATH_t dir = BASE_CMN_TRAFFIC_PATH_INGRESS_EGRESS;

    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DST_INTF,if_nametoindex("e101-009-0"));

    cps_api_attr_id_t ids[3] = {BASE_MIRROR_ENTRY_INTF, 0,BASE_MIRROR_ENTRY_INTF_SRC };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(src_intf),sizeof(src_intf));

    ids[2]=BASE_MIRROR_ENTRY_INTF_DIRECTION;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,&(dir),sizeof(dir));
    //1.1.2.2
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_DESTINATION_IP,0);
    // 1.1.3.1
    cps_api_object_attr_add_u32(obj,BASE_MIRROR_ENTRY_SOURCE_IP,0);
    uint8_t src_mac[]={0,1,2,3,4,5};
    uint8_t dst_mac[]={11,10,9,8,7,6};
    cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_DEST_MAC,(void*)dst_mac,6);
    cps_api_object_attr_add(obj,BASE_MIRROR_ENTRY_SOURCE_MAC,(void *)src_mac,6);

    if(!nas_mirror_exec_transaction(std::string("set"),&tran,obj)) return false;

    return true;
}


bool nas_mirror_rspan_delete(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                       cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &rspan_mirror_id,sizeof(rspan_mirror_id));

    if(!nas_mirror_exec_transaction(std::string("delete"),&tran,obj)) return false;

    return true;
}


bool nas_mirror_erspan_delete(){
    cps_api_transaction_params_t tran;
    if ( cps_api_transaction_init(&tran) != cps_api_ret_code_OK ) return false;

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key,BASE_MIRROR_ENTRY_OBJ,
                                       cps_api_qualifier_TARGET);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL) return false;
    cps_api_object_set_key(obj,&key);
    cps_api_set_key_data(obj,BASE_MIRROR_ENTRY_ID,cps_api_object_ATTR_T_U32,
                                 &erspan_mirror_id,sizeof(erspan_mirror_id));

    if(!nas_mirror_exec_transaction(std::string("delete"),&tran,obj)) return false;

    return true;
}



TEST(nas_mirror_test,nas_span_test) {
    ASSERT_TRUE(nas_mirror_add_test());
    ASSERT_TRUE(nas_mirror_add_same_source_test());
    ASSERT_TRUE(nas_mirror_set_test());
    ASSERT_TRUE(nas_mirror_get_test());
    ASSERT_TRUE(nas_mirror_del_test());
}


TEST(nas_mirror_test, nas_rspan_test){
    ASSERT_TRUE(nas_mirror_rspan_create());
    ASSERT_TRUE(nas_mirror_rspan_set());
    ASSERT_TRUE(nas_mirror_rspan_delete());
}

TEST(nas_mirror_test, nas_erspan_test){
    ASSERT_TRUE(nas_mirror_erspan_create());
    ASSERT_TRUE(nas_mirror_erspan_set());
    ASSERT_TRUE(nas_mirror_erspan_delete());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
