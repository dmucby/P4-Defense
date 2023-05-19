header dns_query1 {
    bit<16> text;
}

header dns_query2 {
    bit<24> text;
}

header dns_query3 {
    bit<32> text;
}

header dns_query4 {
    bit<40> text;
}

header dns_query8 {
    bit<72> text;
}


header_union dnstext_t {
    dns_query1 query1;
    dns_query2 query2;
    dns_query3 query3;
    dns_query4 query4;
    dns_query8 query8;
}
