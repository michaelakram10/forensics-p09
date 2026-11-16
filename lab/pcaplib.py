#!/usr/bin/env python3
"""pcaplib.py - deterministic synthetic-pcap helper (Ethernet/IPv4/TCP/UDP) built on Scapy."""
import hashlib
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

LAN_PREFIX = "192.168.56."
GATEWAY = "192.168.56.1"


def mac_for(ip):
    h = hashlib.md5(ip.encode()).digest()
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(h[:5])      # 02:.. = locally administered


def l2_ip(ip):
    """Off-LAN hosts are reached through the gateway, so their frames carry the gateway MAC."""
    return ip if ip.startswith(LAN_PREFIX) else GATEWAY


class Capture:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.pkts = []
        self.ipid = 1000

    def ip(self, src, dst, l4, ttl=64):
        self.ipid = (self.ipid + 1) & 0xFFFF
        return (Ether(src=mac_for(l2_ip(src)), dst=mac_for(l2_ip(dst)))
                / IP(src=src, dst=dst, ttl=ttl, id=self.ipid, flags="DF") / l4)

    def emit(self, t, pkt):
        pkt.time = t
        self.pkts.append(pkt)

    def udp(self, t, src, sport, dst, dport, payload, ttl=64):
        self.emit(t, self.ip(src, dst, UDP(sport=sport, dport=dport) / Raw(payload), ttl))

    def write(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.chmod(0o644)
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(str(path), self.pkts)
        return len(self.pkts)


class TCP4:
    """One TCP connection with correct seq/ack bookkeeping. self.t is the running clock (epoch seconds)."""
    MSS = 1400

    def __init__(self, cap, t, cip, cport, sip, sport, rtt=0.0006, cttl=64, sttl=64):
        self.cap, self.t, self.rtt = cap, t, rtt
        self.cip, self.cport, self.sip, self.sport = cip, cport, sip, sport
        self.cttl, self.sttl = cttl, sttl
        self.cseq = cap.rng.randint(1_000_000, 2_000_000_000)
        self.sseq = cap.rng.randint(1_000_000, 2_000_000_000)

    def _send(self, from_client, flags, payload=b"", dt=0.0, seq=None):
        self.t += dt
        if from_client:
            l4 = TCP(sport=self.cport, dport=self.sport, flags=flags, window=64240,
                     seq=self.cseq if seq is None else seq, ack=self.sseq if "A" in flags else 0)
            src, dst, ttl = self.cip, self.sip, self.cttl
        else:
            l4 = TCP(sport=self.sport, dport=self.cport, flags=flags, window=65160,
                     seq=self.sseq if seq is None else seq, ack=self.cseq if "A" in flags else 0)
            src, dst, ttl = self.sip, self.cip, self.sttl
        if payload:
            l4 = l4 / Raw(payload)
        self.cap.emit(self.t, self.cap.ip(src, dst, l4, ttl))
        if seq is None:
            adv = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
            if from_client:
                self.cseq += adv
            else:
                self.sseq += adv

    def handshake(self):
        self._send(True, "S")
        self._send(False, "SA", dt=self.rtt)
        self._send(True, "A", dt=0.00004)

    def syn_probe(self, is_open):
        """Half-open (SYN) scan probe: open -> SYN/ACK then RST from scanner; closed -> RST/ACK."""
        self._send(True, "S")
        if is_open:
            self._send(False, "SA", dt=self.rtt)
            self._send(True, "R", dt=0.00004)
        else:
            self._send(False, "RA", dt=self.rtt, seq=0)

    def syn_only(self, gaps=(0.0, 1.0, 2.0)):
        """SYN plus retransmissions (same ISN), never answered (host down / filtered)."""
        isn = self.cseq
        for g in gaps:
            self._send(True, "S", dt=g, seq=isn)

    def data(self, from_client, payload, think=0.0, spacing=0.0002):
        """Send payload split at MSS; the receiver ACKs every segment."""
        self.t += think
        for i in range(0, len(payload), self.MSS):
            self._send(from_client, "PA", payload[i:i + self.MSS], dt=spacing if i else 0.0)
            self._send(not from_client, "A", dt=self.rtt / 2)

    def close(self, client_first=True, dt=0.001):
        a = client_first
        self._send(a, "FA", dt=dt)
        self._send(not a, "A", dt=self.rtt / 2)
        self._send(not a, "FA", dt=0.0002)
        self._send(a, "A", dt=self.rtt / 2)
