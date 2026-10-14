# Alert and response module
# Author: meterpreter

import json
import datetime
import subprocess
import os
from bns.config import LOG_FILE, AUTO_BLOCK

class ResponseHandler:
    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file
        self.blocked = set()

    def handle(self, alerts):
        for alert in alerts:
            alert["timestamp"] = datetime.datetime.utcnow().isoformat()
            self._log(alert)
            self._print(alert)
            if AUTO_BLOCK and alert["severity"] in ("HIGH", "CRITICAL"):
                self._block_ip(alert["src"])

    def _log(self, alert):
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print(self, alert):
        ts = alert["timestamp"]
        print(f"[{ts}] [{alert['severity']}] {alert['type']} "
              f"from {alert['src']} — {alert.get('count', alert.get('ports', ''))}")

    def _block_ip(self, ip):
        if ip in self.blocked or os.geteuid() != 0:
            return
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            self.blocked.add(ip)
            print(f"[BLOCKED] {ip} via iptables")
        except Exception as e:
            print(f"[!] Block failed for {ip}: {e}")
