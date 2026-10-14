# Detection engine: rules + ML anomaly detection
# Author: meterpreter

import time
from collections import defaultdict
from bns.config import (
    SYN_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD, DNS_TUNNEL_THRESHOLD,
    SUSPICIOUS_UA, BANKING_PORTS,
)

class DetectionEngine:
    def __init__(self):
        self.syn_counter = defaultdict(list)      # src -> timestamps
        self.port_tracker = defaultdict(set)       # src -> set of dports
        self.dns_counter = defaultdict(list)       # src -> timestamps
        self.alerts = []

    def _prune(self, lst, window=1.0):
        now = time.time()
        return [t for t in lst if now - t < window]

    def detect(self, rec):
        if rec is None:
            return []
        alerts = []
        src = rec["src"]

        # --- Rule 1: SYN flood ---
        if rec["proto"] == "tcp" and rec["dport"]:
            self.syn_counter[src].append(time.time())
            self.syn_counter[src] = self._prune(self.syn_counter[src])
            if len(self.syn_counter[src]) > SYN_FLOOD_THRESHOLD:
                alerts.append({
                    "type": "SYN_FLOOD", "severity": "HIGH",
                    "src": src, "count": len(self.syn_counter[src]),
                })

        # --- Rule 2: Port scan ---
        if rec["dport"]:
            self.port_tracker[src].add(rec["dport"])
            if len(self.port_tracker[src]) > PORT_SCAN_THRESHOLD:
                alerts.append({
                    "type": "PORT_SCAN", "severity": "MEDIUM",
                    "src": src, "ports": len(self.port_tracker[src]),
                })

        # --- Rule 3: DNS tunneling ---
        if rec["dns_query"]:
            self.dns_counter[src].append(time.time())
            self.dns_counter[src] = self._prune(self.dns_counter[src])
            if len(self.dns_counter[src]) > DNS_TUNNEL_THRESHOLD:
                alerts.append({
                    "type": "DNS_TUNNEL", "severity": "HIGH",
                    "src": src, "queries": len(self.dns_counter[src]),
                })

        # --- Rule 4: Suspicious User-Agent ---
        if rec["http_ua"]:
            for sig in SUSPICIOUS_UA:
                if sig in rec["http_ua"].lower():
                    alerts.append({
                        "type": "SUSPICIOUS_UA", "severity": "MEDIUM",
                        "src": src, "ua": rec["http_ua"],
                    })
                    break

        # --- Rule 5: Banking port access from external IP ---
        if rec["dport"] in BANKING_PORTS and not src.startswith(("10.", "192.168.", "172.")):
            alerts.append({
                "type": "EXTERNAL_BANKING_PORT", "severity": "CRITICAL",
                "src": src, "port": rec["dport"],
                "service": BANKING_PORTS[rec["dport"]],
            })

        return alerts
