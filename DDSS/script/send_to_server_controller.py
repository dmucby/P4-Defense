import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from array import array
import random
import time

sw0 = "s0"
sw1 = "s1"
sw2 = "s2"
sw3 = "s3"
sw4 = "s4"
sw5 = "s5"
sw6 = "s6"
sw7 = "s7"
sw8 = "s8"
#sw=["s0","s1","s2","s3","s4","s5","s6","s7","s8"]

class L3Controller(object):

    def __init__(self):
        self.topo = Topology(db="topology.db")
        #  switch  ID
        self.sw_name = ["s{}".format(i) for i in range(9)]
        # witch  SimpleSwitchAPI
        self.controller = {sw: SimpleSwitchAPI(self.topo.get_thrift_port(sw)) for sw in self.sw_name}



if __name__ == "__main__":
    arr=[1,23,4,5,6,7,8,9,0,242]
    for i in arr[0:-1]:
        print(i)


