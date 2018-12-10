#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Dell Inc.
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

import cps_utils
import nas_os_utils
import nas_common_utils as nas_common
import sys

mirror_type = {"span":"1","rspan":"2"}
direction_type = {"rx":"1","tx":"2","both":"3"}


def nas_mirror_op(op, data_dict,commit=True):
    obj = cps_utils.CPSObject(
        module="base-mirror/entry",
        data=data_dict)
    if commit:
        nas_common.get_cb_method(op)(obj)
    else:
        return obj

def nas_mirror_add_source(obj,intf,direction):
    l = ["intf","0","src"]
    obj.add_embed_attr(l,nas_os_utils.if_nametoindex(intf))
    l[2]="direction"
    obj.add_embed_attr(l,direction_type[direction])

def usage():
    print """\n\ncps_config_mirror.py create [type] [dst_intf] [source_intf] [dir]
                 [vlan_id (if type is rspan)] - creates and returns new mirror session id"""
    print "type - span, rpsan"
    print "dir  - rx,tx,both"
    print "cps_config_mirror.py delete [mirror_id] - delete mirror session"
    print "cps_config_mirror.py set_source [mirror_id] [source_intf] [dir] - change source interface and its direction"
    print "cps_config_mirror.py set_dest [mirror_id] [dst_intf] - change destination interface"
    print "cps_config_mirror.py set_vlan [mirror_id] [vlan_id] - change vlan for rspan mirror session"
    print "cps_config_mirror.py get [mirror_id] - Get Mirror session info"

    exit()

if __name__ == '__main__':

    if len(sys.argv) == 1:
        usage()
    elif sys.argv[1] == "create" and len(sys.argv) >=6:
        obj = nas_mirror_op("create",
                            {"type":mirror_type[sys.argv[2]],
                             "dst-intf":nas_os_utils.if_nametoindex(sys.argv[3])},False)
        nas_mirror_add_source(obj,sys.argv[4],sys.argv[5])
        if sys.argv[2]=="rspan" and len(sys.argv) == 7:
            obj.add_attr("vlan",sys.argv[6])
        elif sys.argv[2] =="rspan" and len(sys.argv) == 6:
            usage()
        print obj.get()
        nas_common.get_cb_method("create")(obj)

    elif sys.argv[1] == "delete" and len(sys.argv) == 3:
        nas_mirror_op("delete", {"id": sys.argv[2]})

    elif sys.argv[1] == "get" and len(sys.argv) == 3:
        nas_mirror_op("get", {"id": sys.argv[2]})

    elif sys.argv[1] == "set_source" and len(sys.argv) == 5:
        obj = nas_mirror_op("set", {"id": sys.argv[2]},False)
        nas_mirror_add_source(obj,sys.argv[3],sys.argv[4])
        print obj.get()
        nas_common.get_cb_method("set")(obj)

    elif sys.argv[1] == "set_dest" and len(sys.argv) == 4:
        nas_mirror_op("set", {"id": sys.argv[2],
                              "dst-intf":nas_os_utils.if_nametoindex(sys.argv[3])})

    elif sys.argv[1] == "set_vlan" and len(sys.argv) == 4:
        nas_mirror_op("set", {"id": sys.argv[2],
                              "vlan":sys.argv[3]})

    else:
        usage()
