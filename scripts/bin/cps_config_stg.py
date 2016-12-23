#!/usr/bin/python
# Copyright (c) 2015 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.

import sys
import nas_stg_utils
import cps_object
import nas_ut_framework as nas_ut
import nas_os_utils

port_state_map = {
    "disabled": "0",
    "listening": "1",
    "learning": "2",
    "forwarding": "3",
    "blocking": "4",
}


def nas_stg_op(op, data_dict, type):
    obj = cps_object.CPSObject(
        module=nas_stg_utils.get_stg_keys()[int(type)],
        data=data_dict)
    obj.add_attr("base-stg/entry/switch-id", "0")
    nas_ut.get_cb_method(op)(obj)


def set_stp_state(stg_id, interface, state):
    obj = cps_object.CPSObject(module=nas_stg_utils.get_stg_keys()[0],
                               data={"switch-id": "0", "id": stg_id})
    el = ["intf", "0", "ifindex"]
    obj.add_embed_attr(el, nas_os_utils.if_nametoindex(interface))
    el[2] = "state"
    obj.add_embed_attr(el, port_state_map[state])
    nas_ut.get_cb_method("set")(obj)


def usage():
    print "\n\ncps_config_stg.py create - creates and returns new stg id"
    print "cps_config_stg.py destroy [stg_id] - delete stg id"
    print "cps_config_stg.py add [stg_id] [vlan_id] - add vlan to stg"
    print "cps_config_stg.py delete [stg_id] [vlan_id] - delete vlan from stg"
    print "cps_config_stg.py set_stp_state [stg_id] [interface_name] [state] -set stp state of interface \nfor a given stg id"
    print "cps_config_stg.py show [stg_id] - show information of given stg id"
    print "[state] - disabled, listening, learning, forwarding, blocking"
    exit()

if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
    elif sys.argv[1] == "create":
        nas_stg_op("create", {}, 0)
    elif sys.argv[1] == "destroy" and len(sys.argv) == 3:
        nas_stg_op("delete", {"id": sys.argv[2]}, 0)
    elif sys.argv[1] == "add" and len(sys.argv) == 4:
        nas_stg_op(
            "create",
            {"base-stg/entry/vlan": sys.argv[3],
             "base-stg/entry/id": sys.argv[2]},
            1)
    elif sys.argv[1] == "delete" and len(sys.argv) == 4:
        nas_stg_op(
            "delete",
            {"base-stg/entry/vlan": sys.argv[3],
             "base-stg/entry/id": sys.argv[2]},
            1)
    elif sys.argv[1] == "set_stp_state" and len(sys.argv) == 5:
        set_stp_state(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "show" and len(sys.argv) == 3:
        nas_stg_op("get", {"id": sys.argv[2]}, 0)
    else:
        usage()
