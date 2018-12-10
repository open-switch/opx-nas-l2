#!/usr/bin/python
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

from cps_utils import *
import argparse

ip_family_map = {
                 "ipv4": 2,
                  "ipv6" : 10
                }

flush_map = {
                "port": 1,
                "port-vlan": 2,
                "vlan": 3,
                "bridge" : 5,
                "bridge-endpoint-ip" : 6,
                "all" : 4,
                "endpoint-ip" : 7,
                "port-vlan-subport" : 8,
                "port-bridge" : 9
            }

def commit(obj, op):
    l = []
    obj_tup = (op, obj.get())
    l.append(obj_tup)
    t = CPSTransaction(l)
    ret = t.commit()
    if ret:
        print "Success"
    else:
        print "Failed"
    return ret


def _create_1q_mac(args, parser):

    if not args.mac or not args.vlan or not args.iface:
        parser.print_help()
        return

    cps_utils.add_attr_type("base-mac/table/mac-address", "mac")
    obj = CPSObject('base-mac/table',
                     data= {"switch-id" : 0, "mac-address" : args.mac,
                       "vlan" : args.vlan, "ifname":args.iface  })
    if args.static:
        obj.add_attr("static",args.static)
    if args.conf_os or args.conf_os_only:
        obj.add_attr("configure-os",1)
    if args.conf_os_only:
        obj.add_attr("configure-npu",0)
    print obj.get()
    return commit(obj, "create")


def _create_1d_mac(args,parser):

    if not args.mac or not args.iface or not args.bridge:
        parser.print_help()
        return

    cps_utils.add_attr_type("base-mac/forwarding-table/mac-address", "mac")
    obj = CPSObject('base-mac/forwarding-table',
                     data= {"switch-id" : 0, "mac-address" : args.mac,
                       "br-name" : args.bridge, "ifname":args.iface  })

    if args.type == "1D-Local":
        if not args.vlan:
            parser.print_help()
            return
        else:
            obj.add_attr("vlan",args.vlan)

    if args.type == "1D-Remote":
        if not args.ip or not args.af:
            parser.print_help()
            return
        else:
            obj.add_attr("base-mac/forwarding-table/endpoint-ip/addr-family",ip_family_map[args.af])
            obj.add_attr_type("base-mac/forwarding-table/endpoint-ip/addr",args.af)
            obj.add_attr("base-mac/forwarding-table/endpoint-ip/addr",args.ip)

    if args.static:
        obj.add_attr("static",args.static)
    if args.conf_os or args.conf_os_only:
        obj.add_attr("configure-os",1)
    if args.conf_os_only:
        obj.add_attr("configure-npu",0)
    print obj.get()
    return commit(obj, "create")


def _delete_mac(args,parser):
    cps_utils.add_attr_type("base-mac/table/mac-address", "mac")
    cps_utils.add_attr_type("base-mac/forwarding-table/mac-address", "mac")
    if args.del_type == "single":
        if args.type == "1Q":
            obj = CPSObject('base-mac/table', data= { "mac-address" : args.mac, "vlan" : args.vlan})
            return commit(obj, "delete")
        else:
            obj = CPSObject('base-mac/forwarding-table', data= {"mac-address" : args.mac,"br-name":args.bridge})
            if args.af:
                obj.add_attr("base-mac/forwarding-table/endpoint-ip/addr-family",ip_family_map[args.af])
                obj.add_attr_type("base-mac/forwarding-table/endpoint-ip/addr",args.af)
                obj.add_attr("base-mac/forwarding-table/endpoint-ip/addr",args.ip)
            print obj.get()
            return commit(obj, "delete")


    obj = CPSObject('base-mac/flush')
    l = ["base-mac/flush/input/filter","0","flush-type"]
    obj.add_embed_attr(l,flush_map[args.del_type])
    if (args.del_type in ["port", "port-vlan" ,"port-vlan-subport", "port-bridge"]) and args.iface:
        l[2]="ifname"
        obj.add_embed_attr(l,args.iface)
        print obj
    if (args.del_type == "vlan" or args.del_type == "port-vlan") and args.vlan:
        l[2]="vlan"
        obj.add_embed_attr(l,args.vlan)
    if (args.del_type == "bridge" or args.del_type == "port-bridge") and args.bridge:
        l[2]="br-name"
        obj.add_embed_attr(l,args.bridge)
        print obj
    if (args.del_type == "bridge-ednpoint-ip" or args.del_type == "endpoint-ip") and args.af and args.ip:
        l[2]="endpoint-ip/addr-family"
        obj.add_embed_attr(l,ip_family_map[args.af])
        obj.add_attr_type("base-mac/flush/input/filter/endpoint-ip/addr",args.af)
        l[2]="endpoint-ip/addr"
        obj.add_embed_attr(l,args.ip)
    print obj.get()
    return commit(obj, 'rpc')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Tool for FDB management')
    parser.add_argument('-o', '--oper', choices = ['create', 'delete', 'update'])
    parser.add_argument('-m','--mac',help=" MAC address")
    parser.add_argument('-i','--iface', help = 'Name of interface')
    parser.add_argument('-b','--bridge', help = 'Name of Bridge')
    parser.add_argument('-t','--type',choices = ["1Q","1D-Local","1D-Remote"], help = 'Type of MAC entry')
    parser.add_argument('--ip', help = 'IP address when type is 1D-Remote')
    parser.add_argument('--af', choices = ["ipv4","ipv6"],help = 'IP address family when type is 1D-Remote')
    parser.add_argument('-v','--vlan',type = int,  help = 'vlan id')
    parser.add_argument('-s','--static',action='store_true',  help = 'Static FDB entry')
    parser.add_argument('--conf-os',action='store_true',  help = 'Configure FDB entry in OS and in NPU')
    parser.add_argument('--conf-os-only',action='store_true',  help = 'Configure FDB entry in OS only')
    parser.add_argument('--del-type',choices = ["port","port-vlan","vlan","bridge","bridge-endpoint-ip","all",
                                                "single","endpoint-ip","port-vlan-subport","port-bridge"],
                        help = 'Delete entry type')

    args = parser.parse_args()

    if not args.type:
        args.type = "1Q"

    if args.oper == 'create':
        if args.type == "1Q":
            _create_1q_mac(args,parser)
        else:
            _create_1d_mac(args,parser)

    elif args.oper == 'update':
        _update_mac(args,parser)

    elif args.oper == 'delete':
        _delete_mac(args,parser)

