# Appendix C.  Connectivity-Check Bandwidth

The tables below show, for IPv4 and IPv6, the bandwidth required for
performing connectivity checks, using different Ta values (given in
ms) and different ufrag sizes (given in bytes).

The results were provided by Jusin Uberti (Google) on 11 April 2016.

                     IP version: IPv4
                     Packet len (bytes): 108 + ufrag
                          |
                       ms |     4     8    12    16
                     -----|------------------------
                      500 | 1.86k 1.98k 2.11k 2.24k
                      200 | 4.64k 4.96k 5.28k  5.6k
                      100 | 9.28k 9.92k 10.6k 11.2k
                       50 | 18.6k 19.8k 21.1k 22.4k
                       20 | 46.4k 49.6k 52.8k 56.0k
                       10 | 92.8k 99.2k  105k  112k
                        5 |  185k  198k  211k  224k
                        2 |  464k  496k  528k  560k
                        1 |  928k  992k 1.06M 1.12M

                     IP version: IPv6
                     Packet len (bytes): 128 + ufrag
                          |
                       ms |     4     8    12    16
                     -----|------------------------
                      500 | 2.18k  2.3k 2.43k 2.56k
                      200 | 5.44k 5.76k 6.08k  6.4k
                      100 | 10.9k 11.5k 12.2k 12.8k
                       50 | 21.8k 23.0k 24.3k 25.6k
                       20 | 54.4k 57.6k 60.8k 64.0k
                       10 |  108k  115k  121k  128k
                        5 |  217k  230k  243k  256k
                        2 |  544k  576k  608k  640k
                        1 | 1.09M 1.15M 1.22M 1.28M


                  Figure 12: Connectivity-Check Bandwidth