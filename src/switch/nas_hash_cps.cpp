/*
 * Copyright (c) 2018 Dell Inc.
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
 * nas_hash_cps.c
 */

#include "dell-base-hash.h"
#include "event_log.h"
#include "event_log_types.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "cps_api_events.h"
#include "nas_ndi_hash.h"
#include <stdbool.h>
#include <stdio.h>


static cps_api_return_code_t nas_hash_set (uint32_t traffic,
                                           BASE_TRAFFIC_HASH_ENTRY_t attr,
                                           cps_api_object_t obj)
{
    uint32_t              lst[BASE_TRAFFIC_HASH_FIELD_MAX];
    size_t                ix = 0;
    cps_api_object_it_t   it;
    t_std_error           rc = STD_ERR_OK;

    /*
     * Extract the hash fields from 'obj' and then call the NAS-NDI SET
     * function, which will call the SAI SET function.
     */
    memset(lst, 0, sizeof(lst));

    for (cps_api_object_it_begin(obj, &it);
         cps_api_object_it_attr_walk(&it, BASE_TRAFFIC_HASH_ENTRY_STD_HASH_FIELD)
             && (ix < (sizeof(lst)/sizeof(*lst)));
         cps_api_object_it_next(&it)) {
        lst[ix++] = cps_api_object_attr_data_u32(it.attr);
    }

    rc = nas_ndi_set_hash_obj(traffic, BASE_TRAFFIC_HASH_FIELD_MAX, lst);
    if (rc != STD_ERR_OK) {
        return((cps_api_return_code_t) rc);
    }

    return cps_api_ret_code_OK;
}


/*
 * SET function
 */
static cps_api_return_code_t nas_cps_set_hash (cps_api_object_t obj)
{
    uint32_t              traffic;
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_attr_t attr;

    /*
     * Valid SET request?
     */
    attr = cps_api_get_key_data(obj, BASE_TRAFFIC_HASH_ENTRY_OBJ_TYPE);
    if (attr == NULL) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH",
                   "Can't get traffic type for SET");
        return cps_api_ret_code_ERR;
    }

    /*
     * Sanity
     */
    traffic = cps_api_object_attr_data_u32(attr);

    if ((traffic < BASE_TRAFFIC_HASH_TRAFFIC_MIN)
        || (traffic > BASE_TRAFFIC_HASH_TRAFFIC_MAX)) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH",
                   "Invalid traffic type %d for SET",
                   (int) traffic);
        return cps_api_ret_code_ERR;
    }

    /*
     * Proceed to extract the arguments
     */
    rc = nas_hash_set(traffic, BASE_TRAFFIC_HASH_ENTRY_STD_HASH_FIELD, obj);
    if (rc != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH", "SET failed");
        return cps_api_ret_code_ERR;
    }

    return rc;
}


static cps_api_object_t create_obj_on_list (cps_api_object_list_t lst,
                                            cps_api_attr_id_t obj_type,
                                            cps_api_qualifier_t qual = cps_api_qualifier_TARGET)
{
    cps_api_object_t o = cps_api_object_list_create_obj_and_append(lst);
    if (o == NULL) {
        return NULL;
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(o),obj_type,qual);
    return o;
}


/*
 * GET function
 */
static cps_api_return_code_t nas_process_cps_hash_get (void *context,
                                                       cps_api_get_params_t *param,
                                                       size_t ix)
{
    cps_api_object_t      filter;
    cps_api_object_attr_t attr;
    t_std_error           rc = STD_ERR_OK;
    uint32_t              std_list[BASE_TRAFFIC_HASH_FIELD_MAX];
    uint32_t              std_count = 0;
    uint64_t              traffic;

    filter = cps_api_object_list_get(param->filters, ix);

    /*
     * Valid GET request?
     */
    attr = cps_api_get_key_data(filter, BASE_TRAFFIC_HASH_ENTRY_OBJ_TYPE);
    if (attr == NULL) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH",
                   "Can't get traffic type for GET");
        return cps_api_ret_code_ERR;
    }

    /*
     * Sanity
     */
    traffic = cps_api_object_attr_data_u32(attr);

    if ((traffic < BASE_TRAFFIC_HASH_TRAFFIC_MIN)
        || (traffic > BASE_TRAFFIC_HASH_TRAFFIC_MAX)) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH",
                   "Invalid traffic type %d for GET", (int) traffic);
        return cps_api_ret_code_ERR;
    }

    rc = nas_ndi_get_hash(traffic, &std_count, std_list);
    if (rc != STD_ERR_OK) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH", "GET call failed");
        return((cps_api_return_code_t) rc);
    }

    /*
     * Fill in the hash fields
     */
    cps_api_object_t obj_std = create_obj_on_list(param->list,
                                                  BASE_TRAFFIC_HASH_ENTRY_STD_HASH_FIELD);
    if (obj_std == NULL) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH", "GET call failed");
        return cps_api_ret_code_ERR;
    }

    for (ix = 0; ix < std_count ; ++ix ) {
        cps_api_object_attr_add_u32(obj_std, BASE_TRAFFIC_HASH_ENTRY_STD_HASH_FIELD,
                                    std_list[ix]);
    }

    return cps_api_ret_code_OK;
}


/*
 * SET function
 */
static cps_api_return_code_t nas_process_cps_hash_set (void *context,
                                                       cps_api_transaction_params_t *param,
                                                       size_t ix)
{
    cps_api_object_t          obj;
    cps_api_operation_types_t op;
    cps_api_return_code_t     rc = cps_api_ret_code_OK;

    obj = cps_api_object_list_get(param->change_list, ix);
    op = cps_api_object_type_operation(cps_api_object_key(obj));

    cps_api_object_t cloned = cps_api_object_list_create_obj_and_append(param->prev);
    if(cloned == NULL) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH", "Null object");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_clone(cloned,obj);

    if (op == cps_api_oper_CREATE) {
        return cps_api_ret_code_OK;
    } else if (op == cps_api_oper_SET) {
        rc = (cps_api_return_code_t) nas_cps_set_hash(obj);
    } else if (op == cps_api_oper_DELETE) {
        return cps_api_ret_code_OK;
    }

    return rc;
}


/*
 * Registration function
 */
t_std_error nas_hash_cps_init (cps_api_operation_handle_t handle)
{
    cps_api_registration_functions_t f;
    char buf[CPS_API_KEY_STR_MAX];

    memset(&f, 0, sizeof(f));

    /* Obtain a key for this object */
    if (!(cps_api_key_from_attr_with_qual(&f.key,
                                          BASE_TRAFFIC_HASH_ENTRY_OBJ,
                                          cps_api_qualifier_TARGET))) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH",
                   "Could not translate %d to key %s",
                   (int) BASE_TRAFFIC_HASH_ENTRY,
                   cps_api_key_print(&f.key, buf, sizeof(buf) - 1));
        return STD_ERR(CPSNAS, FAIL, 0);
    }

    /* Fill in the registration structure's fields */
    f.handle = handle;
    f.context = NULL;
    f._read_function = nas_process_cps_hash_get;
    f._write_function = nas_process_cps_hash_set;
    f._rollback_function = NULL;

    /* Register a callback for this object */
    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        EV_LOGGING(NAS_L2, ERR, "NAS-HASH", "Couldn't register callback");
        return STD_ERR(CPSNAS, FAIL, 0);
    }

    /* SUCCESS */
    return STD_ERR_OK;
}


t_std_error nas_hash_init (cps_api_operation_handle_t handle)
{
    t_std_error rc;

    /*
     * Register callbacks for NAS hashing
     */
    rc = nas_hash_cps_init(handle);
    if (rc != STD_ERR_OK) {
        return rc;
    }

    /*
     * Create and initialise the hash objects
     */
    rc = nas_ndi_create_all_hash_objects();

    return rc;
}

