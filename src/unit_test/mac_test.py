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


import subprocess
import time
import sys
import pytest


class MacUnitTest:

    def _run_cmds(self,in_cmd,ignore_err=False):
        proc = subprocess.Popen(in_cmd.split(),stdout=subprocess.PIPE)
        out,err = proc.communicate()
        if not ignore_err:
            if out.split()[-1] != "Success":
                return False
        return True

    def _setup_ut(self):
        _init_cmds = ["ip link add  link e101-001-0 name e101-001-0.100 type vlan id 100",
                      "brctl addbr br100",
                      "ip link add vtep100 type vxlan id 100 local 10.1.1.2 dstport 4789",
                      "brctl addif br100 vtep100",
                      "brctl addif br100 e101-001-0.100"]
        for i in _init_cmds:
            self._run_cmds(i,True)
        time.sleep(0.5)
        self._run_cmds("bridge fdb add 00:00:00:00:00:00 dev vtep100 dst 10.1.1.1",True)

    def _cleanup_ut(self):
        _cleanup_cmds = ["bridge fdb del 00:00:00:00:00:00 dev vtep100",
                         "brctl delif br100 vtep100",
                         "brctl delif br100 e101-001-0.100",
                         "brctl delbr br100",
                         "ip link del e101-001-0.100",
                         "ip link del vtep100"
                         ]
        for i in _cleanup_cmds:
            self._run_cmds(i,True)

    def __init__(self):
        self._setup_ut()
        self.script_path = "/usr/bin/cps_config_mac.py "
        self.test_ids = ["Create 1D Access","Delete 1D Access",
                         "Create 1D Remote","Delete 1D Remote","Flush Peer IP","Flush PV Subport"]
        self.test_cases = { "Create 1D Access" : "-o create -m 00:00:00:01:02:03 "
                        "-i e101-001-0 -v 100 -b br100 -t 1D-Local" ,
                        "Delete 1D Access" : "-o delete -m 00:00:00:01:02:03 "
                        "-i e101-001-0 -v 100 -b br100 -t 1D-Local --del-type single",
                        "Create 1D Remote": "-o create -m 00:00:00:01:02:04 -i vtep100 "
                         "-b br100 --ip 10.1.1.2 --af ipv4 -t 1D-Remote",
                         "Delete 1D Remote": "-o delete -m 00:00:00:01:02:04 -i vtep100 "
                         "-b br100 --ip 10.1.1.2 --af ipv4 -t 1D-Remote --del-type single",
                         "Flush Peer IP":"-o delete --ip 10.1.1.1 --af ipv4 --del-type endpoint-ip",
                        "Flush PV Subport":"-o delete -i e101-001-0 -v 100 --del-type port-vlan-subport"}

    def _run_test_case(self):
        tc_passed = 0
        tc_failed = 0
        for tc in self.test_ids:
            print "===================================================================="
            print "Running Test Case " + tc
            if self._run_cmds(self.script_path + self.test_cases[tc]):
                print "Passed Test Case " + tc
                tc_passed = tc_passed + 1
            else:
                print "Failed Test Case " + tc
                tc_failed = tc_failed + 1

        print "===================================================================="
        print "Passed Test Cases ", tc_passed
        print "Failed Test Cases ", tc_failed
        self._cleanup_ut()
        if tc_failed:
            return False
        return True



def test_mac_1d_config():
    test = MacUnitTest()
    assert test._run_test_case() == True
