# Protocol dissector for banking traffic
# Author: meterpreter

import math
from collections import Counter
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, HTTPRequest

class TrafficParser:
    def __init__(self):
        self.flows = Counter()  # (src, dst, dport) -> count

    def parse(self, pkt):
        """Return a normalized dict for detection engine."""
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        record = {
            "src": ip.src,
            "dst": ip.dst,
            "size": len(pkt),
            "proto": "other",
            "sport": 0,
            "dport": 0,
            "payload": b"",
            "http_method": None,
            "http_ua": None,
            "dns_query": None,
        }

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record["proto"] = "tcp"
            record["sport"] = tcp.sport
            record["dport"] = tcp.dport
            self.flows[(ip.src, ip.dst, tcp.dport)] += 1

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record["proto"] = "udp"
            record["sport"] = udp.sport
            record["dport"] = udp.dport

        if pkt.haslayer(Raw):
            record["payload"] = bytes(pkt[Raw].load)

        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            record["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore")

        if pkt.haslayer(HTTPRequest):
            record["http_method"] = pkt[HTTPRequest].Method.decode()
            if pkt[HTTPRequest].User_Agent:
                record["http_ua"] = pkt[HTTPRequest].User_Agent.decode(errors="ignore")

        return record

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
