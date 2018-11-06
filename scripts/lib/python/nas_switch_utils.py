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
import cps_object
import cps
import binascii

switch_key_string = "base-switch/switching-entities/switching-entity"

def create_switch_obj():
    return cps_object.CPSObject(module='base-switch/switching-entities/switching-entity')


def create_switch_entities_obj():
    return cps_object.CPSObject(module='base-switch/switching-entities')

obj = create_switch_obj()
obj.add_attr_type('default-vlan-id', 'uint16_t')
obj.add_attr_type('default-mac-address', 'mac')


def create_switch_set_op(args):
    ch = cps_object.CPSObject(
        module='base-switch/switching-entities/switching-entity')
    for i in args:
        l = i.split('=', 1)
        if l[1].find(',') != -1:
            ch.add_list(l[0], l[1].split(','))
        else:
            ch.add_attr(l[0], l[1])
    return ch


def show_switch(args):
    l = []
    obj = create_switch_entities_obj()
    cps.get([obj.get()], l)
    for i in l:
        cps_utils.print_obj(i)

    l = []
    obj = create_switch_obj()
    cps.get([obj.get()], l)
    for i in l:
        cps_utils.print_obj(i)

def print_switch_uft_info(uft_data, switch_mode):
    for mode in uft_data:
        for key in uft_data[mode]:
            value = cps_object.types.from_data(key, uft_data[mode][key])
            print key + ' = ' +  str(value)


def print_switch_details(args):
    switch_mode=['base-switch/switching-entities/switching-entity/switch-mode']

    for key, data in args.items():
        if isinstance(data, dict):
            ''' UFT mode information are stored as a dictionary '''
            print_switch_uft_info(data, switch_mode)
        else:
            value = cps_object.types.from_data(key,data)
            if key in switch_mode:
                if (value == 1):
                    print key + " = cut-through (1)"
                if (value == 2):
                    print key + " = store-and-forward (2)"
            else:
                print key + ' = ' +  str(value)

cps_utils.add_print_function (switch_key_string,print_switch_details)

