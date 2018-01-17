/*
 * Copyright (c) 2017 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mc_util.h
 */

#ifndef __NAS_MC_UTIL_H__
#define __NAS_MC_UTIL_H__

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "cps_api_object.h"
#include "event_log.h"

#define NAS_MC_LOG_EMERG(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, EMERG, ID, __VA_ARGS__)
#define NAS_MC_LOG_ALERT(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, ALERT, ID, __VA_ARGS__)
#define NAS_MC_LOG_CRIT(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, CRIT, ID, __VA_ARGS__)
#define NAS_MC_LOG_ERR(ID, ...)     EV_LOGGING(BASE_MCAST_SNOOP, ERR, ID, __VA_ARGS__)
#define NAS_MC_LOG_WARN(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, WARN, ID, __VA_ARGS__)
#define NAS_MC_LOG_NOTICE(ID, ...)  EV_LOGGING(BASE_MCAST_SNOOP, NOTICE, ID, __VA_ARGS__)
#define NAS_MC_LOG_INFO(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, INFO, ID, __VA_ARGS__)
#define NAS_MC_LOG_DEBUG(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, DEBUG, ID, __VA_ARGS__)

enum class mc_event_type_t
{
    IGMP,
    MLD,
    IGMP_MLD
};

t_std_error nas_mc_proc_init(void);

t_std_error nas_mc_cps_init(void);

void nas_mc_change_snooping_status(mc_event_type_t req_type, hal_vlan_id_t vlan_id, bool enable);
void nas_mc_add_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_del_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_add_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, hal_ifindex_t ifindex);
void nas_mc_del_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, hal_ifindex_t ifindex);
void nas_mc_cleanup_vlan_member(hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_cleanup_interface(hal_ifindex_t ifindex);
void nas_mc_cleanup_vlan(hal_vlan_id_t vlan_id);

#ifdef __cplusplus
extern "C" {
#endif

t_std_error nas_mc_init(void);

#ifdef __cplusplus
}
#endif

#endif
