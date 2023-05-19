/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 32
#define PACKET_THRESHOLD 2
#define BLOOM_FILTER_ENTRIES2 16777216

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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

header udp_t{
        bit<16> sport;
        bit<16> dport;
        bit<16> len;
        bit<16> chksum;
}

struct metadata {
    bit<32> output_hash_one;
    bit<32> output_hash_two;
    bit<8>  syn_defence;
    bit<32> counter_one;
    bit<32> counter_two;
    bit<32> output_hash_three;
    bit<32> counter_three;
    bit<32> output_hash_four;
    bit<32> counter_four;
    bit<32> output_hash_five;
    bit<32> counter_five;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){

            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP:udp;
            default: accept;
        }
    }

    state udp {
           packet.extract(hdr.udp);
           transition accept;
      }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES2) bloom_filter2;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter3;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action updateWhiteList(){
        hash(meta.output_hash_five, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr// hdr.tcp.srcPort,// hdr.tcp.dstPort,//hdr.ipv4.protocol
            },
            (bit<32>)BLOOM_FILTER_ENTRIES);

        bloom_filter3.read(meta.counter_five,meta.output_hash_five);

        if(hdr.tcp.ack == 1){
            meta.counter_five = meta.counter_five + 1;
        }

        bloom_filter3.write(meta.output_hash_five, meta.counter_five);
    }

    action first_drop(){
         hash(meta.output_hash_three, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                            hdr.ipv4.dstAddr
                                                            // hdr.tcp.srcPort,
                                                            // hdr.tcp.dstPort,
                                                            //hdr.ipv4.protocol
                                                            },
                                                            (bit<32>)BLOOM_FILTER_ENTRIES);

        hash(meta.output_hash_four, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.dstAddr,
                                                        hdr.ipv4.srcAddr
                                                        // hdr.tcp.srcPort,
                                                        // hdr.tcp.dstPort,
                                                        //hdr.ipv4.protocol
                                                        },
                                                        (bit<32>)BLOOM_FILTER_ENTRIES);

        bloom_filter2.read(meta.counter_three , meta.output_hash_three * meta.output_hash_four);
        // bloom_filter2.read(meta.counter_four, meta.output_hash_four);

        if(hdr.tcp.ack == 1){
            meta.counter_three = meta.counter_three + 2;
        }else{
            meta.counter_three = meta.counter_three + 1;
        }

        // if(hdr.tcp.ack == 1){
        //     meta.counter_four = meta.counter_four + 2;
        // }else{
        //     meta.counter_four = meta.counter_four + 1;
        // }

        bloom_filter2.write(meta.output_hash_three * meta.output_hash_four, meta.counter_three);
        // bloom_filter2.write(meta.output_hash_four, meta.counter_four);
    }

    table drop_table {
        key ={
            meta.output_hash_three*meta.output_hash_four : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
    }


    action update_bloom_filter(){
       //Get register position
       hash(meta.output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          // hdr.tcp.srcPort,
                                                          // hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol
                                                          },
                                                          (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(meta.output_hash_two, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          // hdr.tcp.srcPort,
                                                          // hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)BLOOM_FILTER_ENTRIES);

        //Read counters
        bloom_filter.read(meta.counter_one, meta.output_hash_one);
        bloom_filter.read(meta.counter_two, meta.output_hash_two);

        if(hdr.tcp.syn == 1){
            meta.counter_one = meta.counter_one + 1;
        }
        if(hdr.tcp.ack == 1){
            meta.counter_two = meta.counter_two + 1;
        }

        //write counters

        bloom_filter.write(meta.output_hash_one, meta.counter_one);
        bloom_filter.write(meta.output_hash_two, meta.counter_two);
    }

    table counters {
        key = {
            meta.output_hash_one:exact;
            meta.output_hash_two:exact;
        }
        actions = {
            update_bloom_filter;
            NoAction;
        }
        size = 1024;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()){
            if (hdr.tcp.isValid()){
                 updateWhiteList();
                 if(meta.counter_five < 1){
                    first_drop();
                    if(meta.counter_three == (bit<32>)1){
                            drop();
                            return;
                    }
                    update_bloom_filter();
                    //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
                    if(meta.counter_one > meta.counter_two){
                        if ( (meta.counter_one - meta.counter_two > PACKET_THRESHOLD)){
                            drop();
                            return;
                        }
                    }
                 }
            }
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
