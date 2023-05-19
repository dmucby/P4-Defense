/*                    switch (hdr.dns_querylen.totalLen) {
                        1: {
                              dns_table1.apply(); }
                        2: {
                              dns_table2.apply(); }
                        3: {
                              dns_table3.apply(); }
                        4: {
                              dns_table4.apply(); }
                    };
*/

            if (hdr.dns_querylen.totalLen == 1)
                 dns_table1.apply();
            else if (hdr.dns_querylen.totalLen == 2)
                  dns_table2.apply();
            else if (hdr.dns_querylen.totalLen == 3)
                  dns_table3.apply();
            else if (hdr.dns_querylen.totalLen == 4)
                  dns_table4.apply();
            else if (hdr.dns_querylen.totalLen == 8)
                  dns_table8.apply();
