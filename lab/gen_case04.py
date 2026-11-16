#!/usr/bin/env python3
"""Case 04: 45 TLS beacons (~60 s +/-20 %) to 203.0.113.50:8443, outage + fallback to 203.0.113.51, tasking, big upload, benign noise."""
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcaplib import Capture, TCP4

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "cases/case04_c2_beacon/raw/case04.pcap"
GT = ROOT / "ground_truth/case04_ground_truth.md"

VIC, C2A, C2B, WEB = "192.168.56.40", "203.0.113.50", "203.0.113.51", "198.51.100.20"
SNI_C2, SNI_WEB = "updates.cdn-lab.test", "www.example.test"
T0 = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc).timestamp()
cap = Capture(seed=404)
rng = cap.rng
iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
rnd = lambda n: rng.randbytes(n)


def rec(ctype, payload):
    return bytes([ctype]) + b"\x03\x03" + struct.pack("!H", len(payload)) + payload


def hs(htype, body):
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def client_hello(sni):
    name = sni.encode()
    ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name      # server_name
    ext += struct.pack("!HHHHH", 10, 6, 4, 0x001D, 0x0017)                                  # supported_groups
    ext += struct.pack("!HHBB", 11, 2, 1, 0)                                                # ec_point_formats
    ext += struct.pack("!HHHH", 13, 4, 2, 0x0804)                                           # signature_algorithms
    body = struct.pack("!H", 0x0303) + rnd(32) + b"\x00" + struct.pack("!H", 4) + struct.pack("!HH", 0xC02F, 0xC030)
    body += b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    return hs(1, body)


def server_hello():
    return hs(2, struct.pack("!H", 0x0303) + rnd(32) + b"\x00" + struct.pack("!H", 0xC02F) + b"\x00")


def tls_session(start, sport, dst, dport, sni, flows, rtt=0.045):
    """flows = [(from_client, nbytes, think_seconds), ...] of opaque Application Data."""
    s = TCP4(cap, start, VIC, sport, dst, dport, rtt=rtt, cttl=128, sttl=57)
    s.handshake()
    s.data(True, rec(22, client_hello(sni)), think=0.002)
    s.data(False, rec(22, server_hello() + hs(14, b"")), think=rtt * 0.6)
    s.data(True, rec(22, hs(16, rnd(66))) + rec(20, b"\x01") + rec(22, rnd(40)), think=0.003)
    s.data(False, rec(20, b"\x01") + rec(22, rnd(40)), think=rtt * 0.6)
    for from_client, nbytes, think in flows:
        for off in range(0, nbytes, 16000):
            s.data(from_client, rec(23, rnd(min(16000, nbytes - off))), think=think if off == 0 else 0.0005)
    s.close(client_first=True, dt=0.02)
    return s.t


log = []
port = 49500
t = T0
for k in range(1, 46):
    dst = C2A if k <= 21 else C2B
    port += 1
    if k in (20, 21):                                    # primary C2 unreachable: SYN + 2 retransmits, no answer
        TCP4(cap, t, VIC, port, dst, 8443, rtt=0.05, cttl=128).syn_only((0.0, 1.0, 2.0))
        log.append((k, t, dst, "UNANSWERED (3x SYN)", "-", "-"))
    else:
        up, down = 340 + rng.choice([0, 16]), 120
        if k == 8:
            down = 4112                                  # tasking: large server -> client record
        if k == 33:
            up = 86000                                   # large client -> server upload (bulk data)
        flows = [(True, up, 0.01), (False, down if k != 33 else 96, 0.25 if k in (8, 33) else 0.12)]
        tls_session(t, port, dst, 8443, SNI_C2, flows)
        log.append((k, t, dst, "ok", up, down if k != 33 else 96))
        if k == 8:                                       # follow-up session 6 s later returns task output
            port += 1
            tls_session(t + 6.0, port, dst, 8443, SNI_C2, [(True, 2064, 0.2), (False, 96, 0.2)])
            log.append((f"{k}b", t + 6.0, dst, "ok (task result)", 2064, 96))
    t += rng.uniform(48, 72)
t_last = t

# ---- benign HTTPS noise: irregular timing, bigger downloads ----
port = 50100
benign = []
for _ in range(6):
    tb = T0 + rng.uniform(30, 2600)
    port += 1
    tls_session(tb, port, WEB, 443, SNI_WEB, [(True, rng.randint(450, 900), 0.02), (False, rng.randint(30000, 200000), 0.06)], rtt=0.03)
    benign.append(tb)

n = cap.write(OUT)
GT.write_text(f"""# SEALED GROUND TRUTH - Case 04
- Generated packets: {n}
- Victim {VIC}; primary C2 {C2A}:8443 (SNI {SNI_C2}); backup C2 {C2B}:8443; benign HTTPS to {WEB}:443 (SNI {SNI_WEB}), 6 sessions
- 45 beacon attempts, interval uniform(48,72) s (mean 60 s). Beacons 1-19 -> primary OK; 20-21 -> primary UNANSWERED; 22-45 -> backup OK
- Beacon 8: tasking (server->client 4112 B), follow-up session 6 s later uploads 2064 B (task result)
- Beacon 33: upload of 86000 B (bulk exfil-like), response 96 B
- Expected Zeek conn.log rows: 46 to port 8443 (44 SF + 2 S0), 6 to port 443 = 52 total
- Expected SYN packets to {C2A}:8443: 26 (20 sessions + 2 failed x 3 SYNs); streams: 22; SYN/ACKs from it: 20
- Beacon table (k | time | dst | status | client bytes | server bytes):
""" + "\n".join(f"  - {k} | {iso(tk)} | {d} | {st} | {u} | {dn}" for k, tk, d, st, u, dn in log) + "\n")
print(f"[case04] wrote {OUT} ({n} packets); beacons {iso(T0)} -> {iso(t_last)}")
