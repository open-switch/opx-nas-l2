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

import cps_utils
import nas_os_utils

sflow_key_string = ["base-sflow/entry"]


def get_sflow_keys():
    return sflow_key_string

def print_obj(obj):
    cps_utils.print_obj(obj)
    cps_obj= cps_utils.CPSObject(obj=obj)
    ifindex = cps_obj.get_attr_data("ifindex")
    ifname = nas_os_utils.if_indextoname(ifindex)
    print "base-sflow/entry/ifname = " + ifname
    print "\n\n"

            
