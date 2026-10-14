# Bank Network Sentinel Configuration
# Author: meterpreter

# Network interface to monitor (use "eth0", "wlan0", or "any")
INTERFACE = "eth0"

# Banking-specific high-risk ports
BANKING_PORTS = {
    443: "HTTPS (banking portal)",
    8443: "HTTPS alt (payment gateway)",
    9000: "ISO 8583 (card transactions)",
    5000: "SWIFT messaging",
    1521: "Oracle DB (core banking)",
    3306: "MySQL (transaction logs)",
    5432: "PostgreSQL (ledger)",
    6379: "Redis (session cache)",
}

# Threat thresholds
SYN_FLOOD_THRESHOLD = 100     # SYN packets per second
PORT_SCAN_THRESHOLD = 15      # distinct ports per source IP
DNS_TUNNEL_THRESHOLD = 50     # DNS queries per second from one host
SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "hydra", "metasploit", "meterpreter", "cobalt", "brute",
]

# ML model
ML_CONTAMINATION = 0.1        # expected anomaly fraction
ML_FEATURES = [
    "pkt_size", "is_tcp", "is_udp", "is_http", "is_dns",
    "port_risk_score", "hour_of_day", "payload_entropy",
]

# Response
AUTO_BLOCK = False            # set True to auto-block via iptables
LOG_FILE = "bns_alerts.json"
