import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField

import random

class L3Controller(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        #  switch  ID
        self.sw_name = ["s{}".format(i+1) for i in range(6)]
        # witch  SimpleSwitchAPI
        self.controller = {sw: SimpleSwitchAPI(self.topo.get_thrift_port(sw)) for sw in self.sw_name}

        self.init()

    def init(self):
        #  s2
        sw = "s2"
        self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])
        # s3
        sw = "s3"
        self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])
        #  s4
        sw = "s4"
        self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])
        #  s5
        sw = "s5"
        self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])

    def random_set(self):
        for controller in self.controller.values():
            controller.reset_state()

        sw1 = "s1"
        sw2 = "s2"
        sw3 = "s2"
        sw4 = "s2"
        sw5 = "s2"
        sw6 = "s2"

        # s1
        self.controller[sw1].table_add("ipv4_lpm","set_nhop",["10.0.1.1/32"],["00:00:0a:00:01:01","1"])
        self.controller[sw1].table_add("ipv4_lpm","ecmp_group",["10.0.6.2/32"],["1","4"])
        self.controller[sw1].table_add("ecmp_group_to_nhop","set_nhop",["1","0"],["00:00:00:02:01:00","2"])
        self.controller[sw1].table_add("ecmp_group_to_nhop","set_nhop",["1","1"],["00:00:00:03:01:00","3"])
        self.controller[sw1].table_add("ecmp_group_to_nhop","set_nhop",["1","2"],["00:00:00:04:01:00","4"])
        self.controller[sw1].table_add("ecmp_group_to_nhop","set_nhop",["1","3"],["00:00:00:05:01:00","5"])

        # s2
        self.controller[sw2].table_add("ipv4_lpm","set_nhop",["10.0.1.1/32"],["00:00:00:01:02:00","1"])
        self.controller[sw2].table_add("ipv4_lpm","set_nhop",["10.0.6.2/32"],["00:00:00:06:02:00","2"])

        # s3
        self.controller[sw3].table_add("ipv4_lpm","set_nhop",["10.0.1.1/32"],["00:00:00:01:03:00","1"])
        self.controller[sw3].table_add("ipv4_lpm","set_nhop",["10.0.6.2/32"],["00:00:00:06:03:00","2"])

        # s4
        self.controller[sw4].table_add("ipv4_lpm","set_nhop",["10.0.1.1/32"],["00:00:00:01:04:00","1"])
        self.controller[sw4].table_add("ipv4_lpm","set_nhop",["10.0.6.2/32"],["00:00:00:06:04:00","2"])

        # s5
        self.controller[sw5].table_add("ipv4_lpm","set_nhop",["10.0.1.1/32"],["00:00:00:01:05:00","1"])
        self.controller[sw5].table_add("ipv4_lpm","set_nhop",["10.0.6.2/32"],["00:00:00:06:05:00","2"])

        # s6
        self.controller[sw6].table_add("ipv4_lpm","set_nhop",["10.0.6.2/32"],["00:00:0a:00:06:02","1"])
        self.controller[sw6].table_add("ipv4_lpm","ecmp_group",["10.0.1.1/24"],["1","4"])
        self.controller[sw6].table_add("ecmp_group_to_nhop","set_nhop",["1","0"],["00:00:00:02:06:00","2"])
        self.controller[sw6].table_add("ecmp_group_to_nhop","set_nhop",["1","1"],["00:00:00:03:06:00","3"])
        self.controller[sw6].table_add("ecmp_group_to_nhop","set_nhop",["1","2"],["00:00:00:04:06:00","4"])
        self.controller[sw6].table_add("ecmp_group_to_nhop","set_nhop",["1","3"],["00:00:00:05:06:00","5"])

        nums = [0,0,0,0,0,0]
        table1 = random.randint(1,4)
        table2 = random.randint(1,4)
        nums[table1] = 1
        nums[table2] = 1

        for i in range(6):
            if(nums[i] == 1):
                sw = "s" + str(i)
                self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])


if __name__ == "__main__":
    controller = L3Controller()
    controller.random_set()
