/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parser_ethernet;
    }

    state parser_ethernet{
        packet.extract(hdr.ethernet);
            transition select(hdr.ethernet.etherType){
                TYPE_IPV4:parser_ipv4;
                default  :accept;
        }
    }
    state parser_ipv4{
        packet.extract(hdr.ipv4);
            transition select(hdr.ipv4.protocol){
                6       :parser_tcp;
                default :accept;
        }
    }

    state parser_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //TODO 3: Deparse the ethernet, ipv4 and tcp headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}
