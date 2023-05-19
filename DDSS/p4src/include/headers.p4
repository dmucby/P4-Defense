/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
#define CPU_REASON_CODE_SFLOW            0x4

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP = 0x1;
// const bit<9>  SYN_FLAG  = 1;
const bit<16> ETH_TYPE_MYTUNNEL = 0x1212;
const bit<16> ICMP_REQ=0x800;
const bit<16> ICMP_RESP=0x0;
#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 32
#define PACKET_THRESHOLD 100
#define PACKET_MAX_THRESHOLD 150
#define PACKET_MIN_THRESHOLD 10
#define BLOOM_FILTER_ENTRIES2 4096


typedef bit<9> port_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header my_tunnel_t {
    bit<16> proto_id;
    bit<32> tun_id;
    bit<1> checked;
    bit<7> sid;
    bit<8> _pad;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
  //  bit<6>    dscp;
   // bit<2>    ecn;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t src_addr;
    ip4Addr_t dst_addr;
}



header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}





header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}









struct metadata {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
    bit<1>  syn_defence_flag;
    bit<14> a;
    bit<32> output_hash_one;
    bit<32> output_hash_two;
    bit<32> counter_one;
    bit<32> counter_two;
    bit<32> output_hash_three;
    bit<32> counter_three;
    bit<32> output_hash_four;
    bit<32> counter_four;
    bit<1> is_to_clean;
    bit<14> ng_hash;
    bit<48>  loc_mac;


    bit<32>icmp_req;
    bit<32>icmp_resp;


}

struct headers {
    ethernet_t   ethernet;
    my_tunnel_t  my_tunnel;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}



