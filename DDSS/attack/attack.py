import os 
import threading
import time
import sys

from more_itertools import distinct_permutations




class Attack_flow(threading.Thread):
    host_id=""
    dst_ip=""

    def __init__(self):
        threading.Thread.__init__(self)

    def __init__(self,host_id,dst_ip):
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()
        self.dst_ip=dst_ip
        self.host_id=host_id


    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u10000 -d 2000 -V  "+self.dst_ip)


    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u32000 -d 346 -V  "+self.dst_ip)  
    def run(self):
        os.system("./host-cmd_s "+self.host_id+" hping3 -S -p ++ -i u108146 -d 1300 -V  "+self.dst_ip)  
            
    def stop(self):
        self._stop_event.set()





def main():
    attack_flow_arr=[]
    host_id_arr=["h01","h01","h11","h11","h12","h21","h21"]

    dst_ip_arr=["10.0.3.32","10.0.3.31","10.0.3.31","10.0.4.41","10.0.4.42","10.0.4.42","10.0.4.41"]

    # for i in range(len(host_id_arr)):
    #     attack_flow=Attack_flow(host_id_arr[i],dst_ip_arr[i])
    #     attack_flow_arr.append(attack_flow)
     
    for i in range(5):
        attack_flow=Attack_flow(host_id_arr[i],dst_ip_arr[i])
        attack_flow_arr.append(attack_flow)   

    for attack_flow in attack_flow_arr:
        attack_flow.start()












if __name__ == "__main__":
    main()


