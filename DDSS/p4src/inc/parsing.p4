    state parse_dnsquery {
        /* extract DNS query text length in DNS packet */
        packet.extract(hdr.dns_querylen);

        transition select (hdr.dns_querylen.totalLen) {
          1: parse_dnsquerytext1;
          2: parse_dnsquerytext2;
          3: parse_dnsquerytext3;
          4: parse_dnsquerytext4;
          8: parse_dnsquerytext8;
        }
    }

    state parse_dnsquerytext1 {
        /* extract DNS query text with 1 byte */
        packet.extract(hdr.dns_querytext.query1);

        transition parse_dnsqueryoptions;
    }

    state parse_dnsquerytext2 {
        /* extract DNS query text with 2 bytes */
        packet.extract(hdr.dns_querytext.query2);

        transition parse_dnsqueryoptions;
    }

    state parse_dnsquerytext3 {
        /* extract DNS query text with 3 bytes */
        packet.extract(hdr.dns_querytext.query3);

        transition parse_dnsqueryoptions;
    }

    state parse_dnsquerytext4 {
        /* extract DNS query text with 4 byte */
        packet.extract(hdr.dns_querytext.query4);

        transition parse_dnsqueryoptions;
    }

    state parse_dnsquerytext8 {
        /* extract DNS query text with 8 byte */
        packet.extract(hdr.dns_querytext.query8);

        transition parse_dnsqueryoptions;
    }
