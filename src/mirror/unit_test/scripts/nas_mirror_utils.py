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


import cps_utils
import struct
import binascii

mirror_key_string = ["base-mirror/entry"]


def get_mirror_keys():
    return mirror_key_string


def print_source_intf(dic):
    for i, j in dic.items():
        print "Source Interface ", struct.unpack("<L", j[16:20])[0], " <-> Direction  ", struct.unpack("<L", j[36:40])[0]


def print_mirror_obj(dic):
    print "======================================================================"
    key = dic['key']
    print "KEY : ", key
    data = dic['data']
    for i, j in data.items():
        if isinstance(j, bytearray):
            if len(j) == 4:
                print i.split("/")[-1], ":", struct.unpack("<L", j[0:4])[0]
            elif len(j) == 6:
                print i.split("/")[-1], ":", binascii.hexlify(j)
        if isinstance(j, dict):
            parse_source_intf(j)

cps_utils.add_print_function(mirror_key_string[0], print_mirror_obj)
