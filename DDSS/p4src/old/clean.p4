/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

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

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_server(macAddr_t dstAddr, egressSpec_t port,ip4Addr_t server_addr) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //send to server
        hdr.ipv4.dst_addr=server_addr;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

    action set_out_port(port_t port) {


        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

    }


    action my_tunnel_ingress(bit<32> tun_id) {
        hdr.my_tunnel.setValid();
        hdr.my_tunnel.tun_id = tun_id;
        hdr.my_tunnel.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETH_TYPE_MYTUNNEL;
    }

    action my_tunnel_egress(bit<9> port,bit<48> dstAddr) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.etherType = hdr.my_tunnel.proto_id;
        hdr.my_tunnel.setInvalid();
       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;
    }


    table t_tunnel_ingress {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            my_tunnel_ingress;
            _drop;
        }
        default_action = _drop();
    }

    table t_tunnel_fwd {
        key = {
            hdr.my_tunnel.tun_id: exact;
        }
        actions = {
            set_out_port;
            my_tunnel_egress;
            _drop;
        }
        default_action = _drop();
    }



  


    action first_drop(){
         hash(meta.output_hash_three, HashAlgorithm.crc16, (bit<16>)0, {
                                                            hdr.ipv4.src_addr,
                                                            hdr.ipv4.dst_addr
                                                            },
                                                            (bit<32>)BLOOM_FILTER_ENTRIES);

        hash(meta.output_hash_four, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.dst_addr,
                                                        hdr.ipv4.src_addr
                                                        },
                                                        (bit<32>)BLOOM_FILTER_ENTRIES);

        bloom_filter2.read(meta.counter_three , meta.output_hash_three * meta.output_hash_four);

        if(hdr.tcp.ack == 1){
            meta.counter_three = meta.counter_three + 2;
        }else{
            meta.counter_three = meta.counter_three + 1;
        }

        bloom_filter2.write(meta.output_hash_three * meta.output_hash_four, meta.counter_three);

    }


    action update_bloom_filter(){
       //Get register position
       hash(meta.output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.src_addr,
                                                          hdr.ipv4.dst_addr,
                                                          hdr.ipv4.protocol
                                                          },
                                                          (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(meta.output_hash_two, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.src_addr,
                                                          hdr.ipv4.dst_addr,
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

        meta.syn_defence_flag = (bit<1>) 1;
    }

    action syn_defence_action() {
        if(meta.counter_one > meta.counter_two){
            if ( (meta.counter_one - meta.counter_two > PACKET_THRESHOLD)){
                meta.a = (bit<14>) 1;
            }
        }
    }

    table syn_counters {
        key = {
            meta.syn_defence_flag:exact;
        }
        actions = {
            syn_defence_action;
            NoAction;
        }
        size = 1024;
    }


    apply {
        if (hdr.ipv4.isValid()){



            if (hdr.ipv4.isValid() && !hdr.my_tunnel.isValid()) {
            // Process only non-tunneled IPv4 packets.
                t_tunnel_ingress.apply();
            }

            if (hdr.my_tunnel.isValid()) {
                // Process all tunneled packets.
                t_tunnel_fwd.apply();
            }





            // if (hdr.tcp.isValid()){
            //     // first_drop();
            //     // if(meta.counter_three == (bit<32>)1){
            //     //     drop();
            //     //     return;
            //     // }
            //     update_bloom_filter();
            //     syn_counters.apply();
            //     if(meta.a == (bit<14>) 1){
            //         drop();
            //         return;
            //     }



            //     if(my_tunnel.isValid()){    //这个是清送往清洗服务器的判断语句，之后再加
                    
                
    
            //         if(my_tunnel.checked!=(bit<1>)1){

            //         }  

            //     }


                
            // }

            



        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
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
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
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
