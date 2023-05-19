    table dns_table1 {
        key = {
            hdr.dns_querytext.query1.text: exact;
        }
        actions = {
            dns_found;
            dns_miss;
            NoAction;
        }
        size = 16;
        default_action = dns_miss();
    }

    table dns_table2 {
        key = {
            hdr.dns_querytext.query2.text: exact;
        }
        actions = {
            dns_found;
            dns_miss;
            NoAction;
        }
        size = 24;
        default_action = dns_miss();
    }

    table dns_table3 {
        key = {
            hdr.dns_querytext.query3.text: exact;
        }
        actions = {
            dns_found;
            dns_miss;
            NoAction;
        }
        size = 32;
        default_action = dns_miss();
    }

    table dns_table4 {
        key = {
            hdr.dns_querytext.query4.text: exact;
        }
        actions = {
            dns_found;
            dns_miss;
            NoAction;
        }
        size = 40;
        default_action = dns_miss();
    }

    table dns_table8 {
        key = {
            hdr.dns_querytext.query8.text: exact;
        }
        actions = {
            dns_found;
            dns_miss;
            NoAction;
        }
        size = 72;
        default_action = dns_miss();
    }
