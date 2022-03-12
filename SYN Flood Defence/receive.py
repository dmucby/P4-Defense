from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.all import IP, TCP, Ether
import time

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


totals = {}
iface = get_if()
# global cnt
cnt = {}

def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)
        last = time.time()

        #filter packets that are sent from this interface. This is done to just focus on the receiving ones.
        #Some people had problems with this line since they set the src mac address to be the same than the destination, thus
        #all packets got filtered here.
        if get_if_hwaddr(iface) == pkt[Ether].src:
            return

        if id_tup not in totals:
            totals[id_tup] = 0
        totals[id_tup] += 1
        cnt[0] += 1

        print ("Received from %s total: %s" %
                (id_tup, totals[id_tup]))
        print(cnt)
        if(cnt[0] % 100 ==0):
            print( " speed: %s " % (100.0 / (time.time()-last)) )

def main():
    cnt[0] = 0
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
