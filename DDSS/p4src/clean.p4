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

    action _drop() {
        mark_to_drop(standard_metadata);
    }


    action set_out_port(port_t port) {


        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

    }

    action set_clean_flag( bit<32> flag){
        meta.is_to_clean=(bit<1>)flag;

    }

    action my_tunnel_ingress(bit<32> tun_id) {
        hdr.my_tunnel.setValid();
        hdr.my_tunnel.tun_id = tun_id;
        hdr.my_tunnel.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETH_TYPE_MYTUNNEL;
    }



    
    action send_to_server(macAddr_t dstAddr, egressSpec_t server_port) {   //送往清洗服务器

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr =  meta.loc_mac;

        hdr.ipv4.tos=(bit<8>) 0;
       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = server_port;

        //send to server
        //hdr.ipv4.dst_addr=server_addr;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

        //去除掉my_tunnel的头部
        hdr.ethernet.etherType = hdr.my_tunnel.proto_id;
        hdr.my_tunnel.setInvalid();

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
        if(hdr.tcp.isValid()){
            if(hdr.tcp.syn == 1){
                meta.counter_one = meta.counter_one + 1;
            }

            if(hdr.tcp.ack == 1){
                meta.counter_two = meta.counter_two + 1;
            }
        }
        if(hdr.icmp.isValid()){
            if(hdr.icmp.typeCode==ICMP_REQ){
                meta.counter_one=meta.counter_one + 1;
                meta.icmp_req=meta.counter_one;
            }
            if(hdr.icmp.typeCode==ICMP_RESP){
                meta.counter_two=meta.counter_two + 1;
                meta.icmp_resp=meta.counter_two;
            }

        }

        //write counters
        bloom_filter.write(meta.output_hash_one, meta.counter_one);
        bloom_filter.write(meta.output_hash_two, meta.counter_two);

        //meta.syn_defence_flag = (bit<1>) 1;


    }


    table server_lpm {
        key = {
            hdr.my_tunnel.tun_id:exact;
        }
        actions = {
            send_to_server;
            _drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action getMac(macAddr_t Mymac){
        meta.loc_mac=Mymac;
    }

    table getInfo{

        key = {
        }

        actions = {
            getMac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table p4_clean {
        key = {
            hdr.my_tunnel.tun_id:exact;
        }
        actions = {
            set_clean_flag;
            _drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }






    apply {
        getInfo.apply();
        if (hdr.ipv4.isValid()){

            

            if (hdr.ipv4.isValid() && !hdr.my_tunnel.isValid()) {   //针对7号端口来的数据包
                t_tunnel_ingress.apply();
                if(standard_metadata.ingress_port==7){
    
                    if(hdr.ipv4.tos!=(bit<8>)1){
                        _drop();
                        return ;
                    }
                    if(hdr.ethernet.srcAddr!=meta.loc_mac){
                        _drop();
                        return ;
                    }


                    hdr.my_tunnel.checked=(bit<1>)1;    
                }



            }


            if (hdr.my_tunnel.isValid()) {
               
                p4_clean.apply();
                if(hdr.my_tunnel.checked!=(bit<1>)1){
                    if(meta.is_to_clean==(bit<1>)1){
                        update_bloom_filter();
                        if (hdr.tcp.isValid()){
                            if(meta.counter_one > meta.counter_two){
                                if ( meta.counter_one - meta.counter_two > PACKET_THRESHOLD){
                                    _drop();
                                    return;
                                }else if(meta.counter_one - meta.counter_two < PACKET_MIN_THRESHOLD){

                                }else{
                                    switch (server_lpm.apply().action_run){
                                        send_to_server: {
                                            return;
                                        }
                                    }
                                }
                            }else{
                                meta.is_to_clean=(bit<1>)0;
                            }
                        }
                        if(hdr.icmp.isValid()){
                            if(meta.icmp_req > meta.icmp_resp){
                                if ( meta.icmp_req-meta.icmp_resp > PACKET_THRESHOLD){
                                    _drop();
                                    return;
                                }
                            }

                            if(meta.icmp_req<meta.icmp_resp){
                                if(meta.icmp_resp-meta.icmp_req>PACKET_THRESHOLD){
                                    _drop();
                                    return;
                                }
                            }

                            if(meta.icmp_req+meta.icmp_resp>PACKET_MAX_THRESHOLD){
                                _drop();
                                return;
                            }
                        }
                    }
                }

                // Process all tunneled packets.
                t_tunnel_fwd.apply();
            }


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
                hdr.ipv4.tos,
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


