#!/usr/bin/env python3
"""Case 01: SYN scan -> 36 failed SSH logins -> successful login -> interactive enumeration session."""
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcaplib import Capture, TCP4

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "cases/case01_ssh_bruteforce/raw/case01.pcap"
GT = ROOT / "ground_truth/case01_ground_truth.md"

ATT, TGT = "192.168.56.10", "192.168.56.20"
T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc).timestamp()
cap = Capture(seed=101)
rng = cap.rng


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


# ---- SSH binary-packet helpers (structurally valid KEXINIT so Zeek's SSH analyzer parses it) ----
def sshstr(b):
    return struct.pack("!I", len(b)) + b


def ssh_pkt(payload):
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack("!IB", len(payload) + 1 + pad, pad) + payload + rng.randbytes(pad)


def kexinit(kex, hostkey, enc, mac, comp):
    nl = lambda s: sshstr(s.encode())
    p = bytes([20]) + rng.randbytes(16)
    p += nl(kex) + nl(hostkey) + nl(enc) + nl(enc) + nl(mac) + nl(mac) + nl(comp) + nl(comp) + nl("") + nl("")
    p += b"\x00" + b"\x00\x00\x00\x00"
    return ssh_pkt(p)


def ecdh_init():
    return ssh_pkt(bytes([30]) + sshstr(rng.randbytes(32)))


def ecdh_reply():
    return ssh_pkt(bytes([31]) + sshstr(rng.randbytes(51)) + sshstr(rng.randbytes(32)) + sshstr(rng.randbytes(83)))


def newkeys():
    return ssh_pkt(bytes([21]))


# Representative (lab-synthetic) algorithm lists. NOT captured from the real tools.
OSSH_C = ("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
          "sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
          "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c",
          "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,"
          "rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
          "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
          "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
          "hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
          "none,zlib@openssh.com,zlib")
LIBSSH_C = ("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
            "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256",
            "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
            "aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com",
            "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            "none")
OSSH_S = ("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
          "sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
          "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com",
          "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
          "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
          "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
          "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
          "none,zlib@openssh.com")

SRV_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
LIBSSH_BANNER = b"SSH-2.0-libssh_0.10.6\r\n"
OSSH_BANNER = b"SSH-2.0-OpenSSH_9.9p1 Debian-3\r\n"


def ssh_open(s, cbanner, ckex):
    """Banner exchange + key exchange up to NEWKEYS (everything after is opaque 'ciphertext')."""
    s.data(False, SRV_BANNER, think=0.003)
    s.data(True, cbanner, think=0.0008)
    s.data(False, kexinit(*OSSH_S), think=0.0015)
    s.data(True, ckex, think=0.0008)
    s.data(True, ecdh_init(), think=0.002)
    s.data(False, ecdh_reply() + newkeys(), think=0.006)
    s.data(True, newkeys(), think=0.002)
    s.data(True, rng.randbytes(52), think=0.004)       # encrypted service request
    s.data(False, rng.randbytes(52), think=0.003)      # encrypted service accept


# ---- Stage 1: half-open SYN scan from a fixed source port ----
PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 139, 443, 445, 3306, 8080]
OPEN = {22, 80}
order = PORTS[:]
rng.shuffle(order)
t = T0
for p in order:
    TCP4(cap, t, ATT, 51234, TGT, p, rtt=0.0004).syn_probe(p in OPEN)
    t += 0.05
scan_end = t

# ---- Stage 2: 36 failed logins, 4 parallel workers (Hydra-like), 1 guess per connection ----
T_BF = T0 + 60
starts = []
for i in range(36):
    start = T_BF + (i // 4) * 2.4 + (i % 4) * 0.05 + rng.uniform(0, 0.1)
    starts.append(start)
    s = TCP4(cap, start, ATT, 40000 + i, TGT, 22, rtt=0.0005)
    s.handshake()
    ssh_open(s, LIBSSH_BANNER, kexinit(*LIBSSH_C))
    s.data(True, rng.randbytes(100 + rng.choice([0, 16, 32])), think=0.12)   # encrypted password attempt
    s.data(False, rng.randbytes(76), think=0.9)                               # encrypted auth failure
    s.close(client_first=True, dt=0.05)

# ---- Stage 3: one successful interactive login with a DIFFERENT client ----
t_succ = starts[-1] + 3.0
s = TCP4(cap, t_succ, ATT, 49302, TGT, 22, rtt=0.0005)
s.handshake()
ssh_open(s, OSSH_BANNER, kexinit(*OSSH_C))
s.data(True, rng.randbytes(116), think=3.2)       # password typed by a human
s.data(False, rng.randbytes(52), think=0.9)       # auth success
s.data(True, rng.randbytes(84), think=0.02)       # channel open + pty request
s.data(False, rng.randbytes(132), think=0.01)
s.data(True, rng.randbytes(100), think=0.02)      # shell request
s.data(False, rng.randbytes(612), think=0.05)     # login banner / prompt
CMDS = [("id", 118), ("uname -a", 196), ("cat /etc/passwd", 2310), ("ls -la /home", 742),
        ("ps aux", 14250), ("netstat -antp", 3124), ("exit", 0)]
cmd_log = []
for cmd, reply in CMDS:
    s.t += rng.uniform(3.0, 8.0)                  # operator think time
    for _ in cmd:                                 # per-keystroke packets (PTY): 36 B up, 36 B echo
        s.data(True, rng.randbytes(36), think=rng.uniform(0.08, 0.25))
        s.data(False, rng.randbytes(36), think=0.0003)
    s.data(True, rng.randbytes(36), think=0.3)    # Enter
    t_enter = s.t
    if reply:
        s.data(False, rng.randbytes(reply), think=rng.uniform(0.01, 0.06))
    cmd_log.append((t_enter, cmd, reply))
s.close(client_first=False, dt=0.05)
t_end = s.t

n = cap.write(OUT)
GT.parent.mkdir(parents=True, exist_ok=True)
GT.write_text(f"""# SEALED GROUND TRUTH - Case 01 (do not open before Week 11)
- Generated packets: {n}
- Scan: {ATT} -> {TGT}, source port 51234, {len(PORTS)} ports {sorted(PORTS)}; open = {sorted(OPEN)}; {iso(T0)} .. {iso(scan_end)}
- Brute force: 36 failed SSH connections to port 22, 4 parallel workers, 1 guess per connection
  - first start {iso(starts[0])}, last start {iso(starts[-1])}; client banner {LIBSSH_BANNER.decode().strip()}
- Successful login: start {iso(t_succ)}, end {iso(t_end)}; client banner {OSSH_BANNER.decode().strip()} (different client = operator took over)
- Interactive commands (invisible on the wire; only reply sizes are visible):
""" + "\n".join(f"  - {iso(te)}  `{c}`  reply ~{r} B" for te, c, r in cmd_log) + f"""
- Synthetic "passwd-style" data: the reply to `cat /etc/passwd` (~2310 B), which is NOT recoverable from encrypted SSH.
- Expected Zeek conn.log rows: 13 (scan) + 36 (failed) + 1 (success) = 50; rows to port 22 = 38
""")
print(f"[case01] wrote {OUT} ({n} packets); success session {iso(t_succ)} -> {iso(t_end)}")
