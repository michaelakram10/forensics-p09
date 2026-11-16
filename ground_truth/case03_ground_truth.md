# SEALED GROUND TRUTH - Case 03
- Generated packets: 484   (242 DNS transactions = 40 baseline + 202 tunnel)
- Victim 192.168.56.40 -> resolver 192.168.56.53:53/udp; tunnel parent domain `t.exfil-lab.test` (registered domain exfil-lab.test)
- Baseline traffic: 2026-11-05 10:00:19.899Z .. 2026-11-05 10:09:56.205Z (40 A queries, TTL 300)
- Tunnel: 2026-11-05 10:10:00.000Z .. 2026-11-05 10:10:47.848Z; format `sNNNN.<base32 label 56>.<base32 label 56>.t.exfil-lab.test`, qtype TXT, responses TXT `aNNNN`
- Queries: 1 init + 200 data + 1 fin = 202; 70 raw bytes per data query -> 14000 bytes total
- Secret sha256 = 8d8b129b78610da1d7dad75ca2375c25be120b2cdc1f7a3869b974d1b6b32f97
- Tunnel query frame bytes (Ethernet included) = 39367; DNS payload bytes = 30883; IP bytes = 36539
