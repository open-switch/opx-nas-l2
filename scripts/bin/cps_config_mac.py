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

import cps
import os
from cps_utils import *
import sys
import nas_os_utils

set_action = {
    "drop"      : "1",
    "forward"   : "2",
    "trap"      : "3",
    "log"       : "4",
    "default"   : "2"
}

def commit(obj, op):
    l = []
    obj_tup = (op, obj.get())
    l.append(obj_tup)
    t = CPSTransaction(l)
    ret = t.commit()
    if ret:
        print "success"
    return ret


def usage():
    print"\n\n cps_config_mac.py [create | set ] [mac <mac-address>] [port <port>] [vlan <vlan-id>] [static | dynamic]"
    print"\n                          [configure-os]"
    print"\n                          [action <drop | forward | trap | log | source_drop | default>]"
    print"\n\n cps_config_mac.py delete [all] [vlan <vlanid>] [port <port>] [mac <mac-address>] [static | dynamic]"
    print "\n               eg : cps_config_mac.py delete vlan 100 static "
    print "\n                    cps_config_mac.py delete vlan 100 port e101-007-0 "
    print "\n                    cps_config_mac.py delete static"
    print"\n\n cps_config_mac.py show [vlan <vlanid>] [port <port>] [mac <mac-address>] [all][count] [static | dynamic]"
    print"\n\n"


def create_mac_addr(macAddr, vlan, port, action,static,static_type,os_configure,op):

    cps_utils.add_attr_type("base-mac/table/mac-address", "mac")
    if not static_type:
        static = 1
    obj = CPSObject('base-mac/table',
                     data= {"switch-id" : 0, "mac-address" : macAddr,
                       "vlan" : vlan,  "static" : static,  })
    if port:
        obj.add_attr("ifname",port)
    if action:
        obj.add_attr("actions",set_action[action])
    if os_configure:
        obj.add_attr("configure-os",os_configure)
    print obj.get()
    commit(obj, op)
    return


def handle_count(vlan, port, mac_valid, mac, all, static, static_type):
    get = []
    get_obj = CPSObject("base-mac/query")
    get_obj.add_attr_type("mac-address", "mac")
    if (vlan != 0):
        get_obj.add_attr("vlan", vlan)
    if (port != 0):
        index = nas_os_utils.if_nametoindex(port)
        get_obj.add_attr("ifindex", index)
    if (mac_valid == 1):
        get_obj.add_attr("mac-address", mac)
    if (static_type == 1):
        get_obj.add_attr("static", static)
    get_obj.add_attr("request-type", 4)
    print get_obj.get()
    if cps.get([get_obj.get()], get):
        for i in get:
            print_obj(i)
            print "\n\n"
    else:
        print("\n no objects received")


def handle_delete(vlan, port, mac_valid, mac, all, static, static_type):
    obj = CPSObject("base-mac/table")
    obj.add_attr_type("mac-address", "mac")
    if (vlan != 0):
        obj.add_attr("vlan", vlan)
        obj.add_attr("request-type", 1)
    if (port != 0):
        index = nas_os_utils.if_nametoindex(port)
        obj.add_attr("ifindex", index)
        obj.add_attr("request-type", 3)
    if (mac_valid == 1):
        obj.add_attr("mac-address", mac)
        obj.add_attr("request-type", 2)
    if (all == 1):
        obj.add_attr("request-type", 5)
    if (static_type == 1):
        obj.add_attr("static", static)

    print obj.get()
    commit(obj, "delete")
    return


def handle_show(vlan, port, mac_valid, mac, all, static, static_type):
    get = []
    get_obj = CPSObject("base-mac/query")
    get_obj.add_attr_type("mac-address", "mac")
    if (vlan != 0):
        get_obj.add_attr("vlan", vlan)
        get_obj.add_attr("request-type", 1)
    if (port != 0):
        index = nas_os_utils.if_nametoindex(port)
        get_obj.add_attr("ifindex", index)
        get_obj.add_attr("request-type", 3)
    if (mac_valid == 1):
        get_obj.add_attr("mac-address", mac)
        get_obj.add_attr("request-type", 2)
    if (static_type == 1):
        get_obj.add_attr("static", static)
    print get_obj.get()
    print("\n calling get \n")
    if cps.get([get_obj.get()], get):
        print("\n get returned true\n")
        for i in get:
            print_obj(i)
            print "\n\n"
    else:
        print("\n no objects received")


if __name__ == '__main__':
    vlan_id = port = static = count = all = mac_valid = show = static_type = os_configure = 0
    mac = ""
    action = 0
    if len(sys.argv) == 1:
        usage()
    else:
        if sys.argv[1] == "create" or sys.argv[1]=="set":
           arglen = len(sys.argv)
           if arglen < 7:
              usage()
           else:
              i = 2
              while (i < arglen):
                  if (sys.argv[i] == "mac"):
                      i = i+1
                      mac = sys.argv[i]
                  elif (sys.argv[i] == "port"):
                      i = i+1
                      port = sys.argv[i]
                  elif (sys.argv[i] == "vlan"):
                      i = i+1
                      vlan_id = sys.argv[i]
                  elif (sys.argv[i] == "action"):
                      i = i+1
                      action = sys.argv[i]
                  elif (sys.argv[i] == "static"):
                      static = 1
                      static_type = 1
                  elif (sys.argv[i] == "dynamic"):
                      static = 0
                      static_type = 1
                  elif (sys.argv[i] == "configure-os"):
                      os_configure = 1
                  i = i+1
              create_mac_addr(mac, vlan_id, port, action,static,static_type,os_configure,sys.argv[1])
        elif (sys.argv[1] in ["show", "delete"]):
            print("len = ", len(sys.argv))
            print("command : ", sys.argv[1])
            arglen = len(sys.argv)
            if (sys.argv[1] == "show"):
                show = 1
            if (sys.argv[1] == "delete"):
                delete = 1
            i = 2
            while (i < arglen):
                print("\n iteration i", i)
                if (arglen == 2):
                     # show all  static and dynamic
                    static_type = 0
                elif (sys.argv[i] == "vlan"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n Please reenter with vlan id"
                    vlan_id = sys.argv[i]
                elif (sys.argv[i] == "port"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n please reenter with port name"
                    port = sys.argv[i]
                elif (sys.argv[i] == "mac"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n please enter mac address in a:b:c:d:e:f format"
                    mac = sys.argv[i]
                    mac_valid = 1
                elif (sys.argv[i] == "all"):
                    all = 1
                elif (sys.argv[i] == "count"):
                    count = 1
                elif (sys.argv[i] == "static"):
                    static = 1
                    static_type = 1
                elif (sys.argv[i] == "dynamic"):
                    static = 0
                    static_type = 1
                i = i + 1
            print(
                "\n\n show vlan with vlan port mac all static ",
                vlan_id,
                port,
                mac_valid,
                mac,
                all,
                count,
                static)
            if (count):
                print("\n count command")
                handle_count(
                    vlan_id,
                    port,
                    mac_valid,
                    mac,
                    all,
                    static,
                    static_type)

            elif (show):
                print("\n show command")
                handle_show(
                    vlan_id,
                    port,
                    mac_valid,
                    mac,
                    all,
                    static,
                    static_type)
            elif (delete):
                print("\n delete command")
                handle_delete(
                    vlan_id,
                    port,
                    mac_valid,
                    mac,
                    all,
                    static,
                    static_type)
        else:
            usage()
