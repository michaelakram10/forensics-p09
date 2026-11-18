# Verification Report - case03_dns_tunnel

## Results
Zeek (dns.log, conn.log) compared with tshark on `raw/case03_dns_tunnel.pcap`.

| Check | Zeek | tshark | Match |
|---|---|---|---|
| DNS queries | 445 | 445 | Yes |
| DNS responses | 445 (all NOERROR) | 445 | Yes |
| CNAME / MX / TXT | 164 / 150 / 131 | 164 (type 5) / 150 (type 15) / 131 (type 16) | Yes |
| First query | 18:25:25.008145 UTC | epoch 1795026325.008145 | Yes |
| Last query | 18:30:23.513247 UTC | epoch 1795026623.513247 | Yes |
| Longest names | 240, 240, 181, 155, 155 | 240, 240, 181, 155, 155 | Yes |
| Flow | 1 flow, udp/53, 298.506573 s, 27,322 B out, 52,063 B in | not compared | n/a |

## Summary
All compared values agree between the two tools. No discrepancies were found.

## Interpretation
Zeek and tshark independently reproduce the same query count, type distribution, timestamps and longest names, so the Zeek-based reconstruction is supported by the raw packets. Timezone note: `capinfos` prints the VM's local time (UTC-5, 13:25 to 13:30); all other times in this report are UTC. Zeek's flow byte counts were not independently recomputed from packets.
