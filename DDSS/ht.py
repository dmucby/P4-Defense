
import pyshark
import collections
import matplotlib.pyplot as plt
import numpy as np
import time
 





# cap1 = pyshark.FileCapture('pcap/s0-eth5_in.pcap', only_summaries=True)
# cap2 = pyshark.FileCapture('pcap/s1-eth1_in.pcap', only_summaries=True)
# cap3 = pyshark.FileCapture('pcap/s1-eth2_in.pcap', only_summaries=True)
# cap4 = pyshark.FileCapture('pcap/s2-eth2_in.pcap', only_summaries=True)

# cap5 = pyshark.FileCapture('pcap/s4-eth5_in.pcap', only_summaries=True)
# cap6 = pyshark.FileCapture('pcap/s4-eth4_in.pcap', only_summaries=True)
# cap7 = pyshark.FileCapture('pcap/s3-eth4_in.pcap', only_summaries=True)


#cap = pyshark.FileCapture('pcap/s2-eth3_in.pcap', only_summaries=True)
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

attack_src_ip_arr=["10.0.9.1","10.0.9.1","10.0.1.11","10.0.1.11","10.0.1.12","10.0.2.21","10.0.2.21"]
attack_dst_ip_arr=["10.0.3.32","10.0.3.31","10.0.3.31","10.0.4.41","10.0.4.42","10.0.4.42","10.0.4.41"]



protocolList = [[],[]]
ipsrcList=[[],[]]
ipdstList=[[],[]]

cap_list=['pcap/s0-eth5_out.pcap','pcap/s1-eth1_out.pcap','pcap/s1-eth2_out.pcap','pcap/s2-eth2_out.pcap','pcap/s4-eth5_in.pcap','pcap/s4-eth4_in.pcap','pcap/s3-eth4_in.pcap','pcap/s3-eth5_in.pcap']

count=0
count_list=[[0,0,0,0,0,0,0],[0,0,0,0,0,0,0]]
my_count=[0,0]

for cap_name_id in range(len(cap_list)):
    flag=0
    cap = pyshark.FileCapture(cap_list[cap_name_id], only_summaries=True)
    if(cap_name_id<=3):
        flag=0
    else:
        flag=1
    for packet in cap:
        line = str(packet)
        # time.sleep(0.5)
        # print(packet)
        formattedLine = line.split(" ")
        ipsrcList[flag].append(formattedLine[2])
        ipdstList[flag].append(formattedLine[3])
        protocolList[flag].append(formattedLine[4])
        my_count[flag]+=1



for i in range(len(ipsrcList[0])):
    for j in range(len(attack_dst_ip_arr)):
        if(ipsrcList[0][i]==attack_src_ip_arr[j] and ipdstList[0][i]==attack_dst_ip_arr[j]):
            print("where")
            count_list[0][j]+=1

for i in range(len(ipsrcList[1])):
    for j in range(len(attack_dst_ip_arr)):
        if(ipsrcList[1][i]==attack_src_ip_arr[j] and ipdstList[1][i]==attack_dst_ip_arr[j]):
            print("where1")
            count_list[1][j]+=1

print(len(ipsrcList[0]))
print(len(ipsrcList[1]))


x_data=["flow1","flow2","flow3","flow4","flow5","flow6","flow7"]
 

x_width = range(0,len(x_data))
x2_width = [i+0.3 for i in x_width]

y_data=count_list[0]
y2_data=count_list[1]

plt.bar(x_width,y_data,lw=0.5,fc="r",width=0.3,label="attack_flow")
plt.bar(x2_width,y2_data,lw=0.5,fc="b",width=0.3,label="accept_attack_flow")
 
plt.xticks(range(0,7),x_data)



plt.ylabel("flow_count")
plt.xlabel("flow_name")
plt.savefig("result.png")


print(my_count[0])
print(my_count[1])




