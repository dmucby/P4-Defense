
import nnpy
import struct
import sys
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from array import array
import random
import time
import threading
import os
import string



g=7
n=3
interval=10


class suppress_stdout_stderr(object):
    '''
    A context manager for doing a "deep suppression" of stdout and stderr in
    Python, i.e. will suppress all print, even if the print originates in a
    compiled C/Fortran sub-function.
       This will not suppress raised exceptions, since exceptions are printed
    to stderr just before a script exits, and after the context manager has
    exited (at least, I think that is why it lets exceptions through).

    '''
    def __init__(self):
        # Open a pair of null files
        self.null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        # Save the actual stdout (1) and stderr (2) file descriptors.
        self.save_fds = (os.dup(1), os.dup(2))

    def __enter__(self):
        # Assign the null pointers to stdout and stderr.
        os.dup2(self.null_fds[0], 1)
        os.dup2(self.null_fds[1], 2)

    def __exit__(self, *_):
        # Re-assign the real stdout/stderr back to (1) and (2)
        os.dup2(self.save_fds[0], 1)
        os.dup2(self.save_fds[1], 2)
        # Close the null files
        os.close(self.null_fds[0])
        os.close(self.null_fds[1])


class L3Controller(object):
    sw=["s0","s1","s2","s3","s4","s5","s6","s7","s8"]
    defence_task=[[],[],[],[],[],[],[],[],[],[]]

    last_defence_task=[[],[],[],[],[],[],[],[],[],[]]
    sw_load=[0,0,0,0,0,0,0,0,0]

    defence_task_entry=[[],[],[],[],[],[],[],[],[],[]]

    dst_ip_arr = [
	"10.0.9.1",
	"10.0.1.11",
	"10.0.1.12",
	"10.0.2.21",
	"10.0.2.22",
    "10.0.3.31",
	"10.0.3.32",
	"10.0.4.41",
	"10.0.4.42"]
    n=0

    attack_tunid=[5,6,14,16,17,25,26]

    select_flow=[]

    route=[[0,9],
    [0,1,10],
    [0,1,11],
    [0,1,2,12],
    [0,6,7,3,2,13],
    [0,6,7,3,14],
    [0,6,7,3,15],
    [0,5,4,16],
    [0,5,4,17],
    [1,0,9],
    [1,10],
    [1,11],
    [1,2,12],
    [1,2,13],
    [1,6,7,3,14],
    [1,2,3,15],
    [1,6,7,4,16],
    [1,6,7,4,17],
    [2,6,0,9],
    [2,1,10],
    [2,1,11],
    [2,12],
    [2,13],
    [2,3,14],
    [2,3,15],
    [2,6,7,4,16],
    [2,6,7,5,4,17],
    [3,7,8,0,9],
    [3,2,1,10],
    [3,2,1,11],
    [3,2,12],
    [3,2,13],
    [3,14],
    [3,15],
    [3,4,16],
    [3,4,17],
    [4,5,0,9],
    [4,3,2,1,10],
    [4,7,6,1,11],
    [4,3,2,12],
    [4,3,2,13],
    [4,3,14],
    [4,3,15],
    [4,16],
    [4,17],
    [5,0,9],
    [5,0,1,10],
    [5,0,1,11],
    [5,0,1,2,12],
    [5,8,6,2,13],
    [5,4,3,14],
    [5,7,3,15],
    [5,4,16],
    [5,4,17],
    [6,0,9],
    [6,1,10],
    [6,1,11],
    [6,2,12],
    [6,2,13],
    [6,2,3,14],
    [6,7,3,15],
    [6,7,4,16],
    [6,7,4,17],
    [7,8,0,9],
    [7,6,1,10],
    [7,6,1,11],
    [7,3,2,12],
    [7,6,2,13],
    [7,3,14],
    [7,3,15],
    [7,4,16],
    [7,4,17],
    [8,0,9],
    [8,6,1,10],
    [8,6,1,11],
    [8,6,2,12],
    [8,6,2,13],
    [8,7,3,14],
    [8,7,3,15],
    [8,7,4,16],
    [8,7,4,17]
    ]


    def init_server_lpm(self):
        for i in self.sw:
            for j in range(100):
                tmp_arr=[]
                tmp_arr.append(str(j))
                self.controller[i].table_add("server_lpm","send_to_server",tmp_arr,["00:0c:29:aa:72:f3","7"])


 









    def __init__(self):
        self.topo = Topology(db="topology.db")
        #  switch  ID
        self.sw_name = ["s{}".format(i) for i in range(9)]
        # witch  SimpleSwitchAPI
        self.controller = {s: SimpleSwitchAPI(self.topo.get_thrift_port(s)) for s in self.sw_name}
        self.init_port()
        self.init_server_lpm()









    def init_port(self):
        self.controller[self.sw[0]].port_add("eth1",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[1]].port_add("eth2",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[2]].port_add("eth3",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[3]].port_add("eth4",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[4]].port_add("eth5",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[5]].port_add("eth6",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[6]].port_add("eth7",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[7]].port_add("eth8",7, pcap_path='/home/user/Desktop/test/pcap')
        self.controller[self.sw[8]].port_add("eth9",7, pcap_path='/home/user/Desktop/test/pcap')
	







    def init_defence_task(self):
        n = 9

        m = len(self.route)
        self.defence_task_entry= [[0]*m for i in range(n)]
        for i in range(9):
            for tun_id in range(len(self.route)):
                tmp_arr=[]
                tmp_arr.append(str(tun_id))
                entry_key=self.controller[self.sw[i]].table_add("p4_clean","set_clean_flag",tmp_arr,["0"])
                self.defence_task_entry[i][tun_id]=entry_key


    def modify_task(self,sw_id,tun_id):
        entry_key=self.defence_task_entry[sw_id][tun_id]
        self.defence_task_entry[sw_id][tun_id]=self.controller[self.sw[sw_id]].table_modify("p4_clean","set_clean_flag",entry_key,["1"])
        

        
    def table_update(self,swid):
        self.sw_load[swid]=0
        for tun_id in self.defence_task[swid]:
            self.modify_task(swid,tun_id)
        #time.sleep(0.5)

            
    def table_clear(self,swid):
        for tun_id in self.last_defence_task[swid]:
            if (tun_id not in self.defence_task[swid]): 
                entry_key=self.defence_task_entry[swid][tun_id]
                entry_key=self.controller[self.sw[swid]].table_modify("p4_clean","set_clean_flag",entry_key,["0"])
                self.defence_task_entry[swid][tun_id]=entry_key

    def print_defence_task(self):
        sss=0
        print("-"*99)
        print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
        for arr in self.defence_task:
            print("switch s"+str(sss)+" assigned:")
            print(arr)
            sss+=1


        print("-"*99)

    def dynamic_control(self):   
        self.init_defence_task()
        global n
        global interval
        
        while(True):
            with suppress_stdout_stderr():
                self.n=n
                print("-"*99)


                tmp_arr=range(len(self.attack_tunid))
                random.shuffle(tmp_arr)
                self.select_flow=[self.attack_tunid[j] for j in tmp_arr[0:int(self.n)]]
                print(self.select_flow)


                    
                
                self.last_defence_task=self.defence_task

                self.defence_task=[[],[],[],[],[],[],[],[],[],[]]


                # for tun_id in self.select_flow:
                #     select_sw=self.route[tun_id][0]
                #     for i in self.route[tun_id][0:-1]:
                #         if(self.sw_load[i]<self.sw_load[select_sw]):
                #             select_sw=i
                #     self.modify_task(select_sw,tun_id)
                #     self.sw_load[select_sw]+=1
                #     self.defence_task[select_sw].append(tun_id)
                    
                for tun_id in self.select_flow:
                    select_sw=self.route[tun_id][0]
                    self.modify_task(select_sw,tun_id)

                    self.defence_task[select_sw].append(tun_id)

                
                self.select_flow=[]


                for i in range(9):
                    self.table_update(i)
                

                for i in range(9):
                    self.table_clear(i)




                sss=0
                print("-"*99)
                print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
                for arr in self.defence_task:
                    print("switch s"+str(sss)+" assigned:")
                    print(arr)
                    sss+=1


                print("-"*99)
            time.sleep(interval)

            
class Controller(threading.Thread):

    controller=None
    def __init__(self):
        threading.Thread.__init__(self)
        self.controller = L3Controller()


    def run(self):
        self.controller.dynamic_control()
      
    def print_defence_task(self):
        self.controller.print_defence_task()

    def stop():
        threading.Thread._stop()




def main():
    global g
    global n
    global interval
    
    main_controller=Controller()
    main_controller.setDaemon(True)
    main_controller.start()
    time.sleep(3)
    i=os.system("clear")
    #i=os.system("clear")
    while(True):
        cmd = raw_input('cmd:')
        if(cmd=='hello'):
            print("hello!")
        elif(cmd=='set_g'):
            g=int(input("g:"))
        elif(str(cmd)=='set_n'):
            n=int(input("n:"))
        elif(str(cmd)=="help"):
            print("set_g:\t\tset the num g  \n \nset_n:\t\tset the num n \n \nset_interval:\tset the tiaobian de interval \n\nhello:\t\treponse with hello \n\nclear:\t\tclear the cmd screen \n\nexit:\t\tstop the controller and exit\n\nhelp:\t\tyou have tried it right?")
        elif(str(cmd)=="exit"):
            break
        elif(str(cmd)=="clear"):
            i=os.system("clear")
        elif(str(cmd)=="defence_task"):
            main_controller.print_defence_task()
        elif(str(cmd)=="set_interval"):
            interval=int(input("interval:"))
        else:
            print("wrong cmd! try \'help\' ")
            print(str(cmd) + " is not defined !")

    print("defence terminal stop!")



if __name__ == "__main__":
    main()
    

