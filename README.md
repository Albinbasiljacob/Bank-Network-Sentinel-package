<div align="center">

# 🏦 Bank Network Sentinel (BNS)

**Real-time network security monitoring and intrusion detection built for banking environments.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/scapy-2.5.0-green.svg)](https://scapy.net/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Author](https://img.shields.io/badge/author-meterpreter-purple.svg)](#author)

*A domain-aware IDS that understands ISO 8583, SWIFT, and core banking port classifications — and treats external access to them as critical, because in banking, context is everything.*

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Why BNS?](#-why-bns)
- [Features](#-features)
- [Architecture](#-architecture)
- [Detection Rules](#-detection-rules)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Testing](#-testing)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🔍 Overview

**Bank Network Sentinel (BNS)** is a lightweight, offline-first Intrusion Detection System (IDS) purpose-built for banking and financial network environments.

Unlike general-purpose tools such as Snort or Suricata — which flag ports and protocols in isolation — BNS encodes **domain knowledge** about the financial services stack. It knows that:

- Port **9000** carries **ISO 8583** card transaction traffic
- Port **5000** carries **SWIFT** interbank messaging
- Port **1521** and **3306** are **core banking databases** (Oracle / MySQL)
- Port **8443** is a **payment gateway HTTPS endpoint**

When external IPs touch these ports, BNS doesn't just log an "open port" — it raises a **CRITICAL** alert, because in banking, that's a potential fraud vector.

BNS is designed for **air-gapped and restricted environments**, requires **no cloud dependencies**, and runs entirely on the local network.

---

## 🎯 Why BNS?

| Feature | Generic IDS (Snort/Suricata) | **Bank Network Sentinel** |
|---------|------------------------------|---------------------------|
| Port classification | Generic (open/closed) | **Banking-aware** (ISO 8583, SWIFT, CDE ports) |
| PCI-DSS context | ❌ None | ✅ Ports mapped to **Cardholder Data Environment** boundaries |
| Offline capable | ✅ Yes | ✅ Yes (no cloud, no API keys) |
| Auto-response | ⚠️ Requires config | ✅ Built-in **iptables DROP** on HIGH/CRITICAL |
| Rule authoring | Complex DSL | ✅ **5-line Python rules** in `config.py` |
| ML anomaly detection | ⚠️ Add-on | ✅ **Isolation Forest** built-in (roadmap) |

BNS is **narrower but deeper** than Snort. It's not trying to replace it — it's trying to speak the language of a bank SOC.

---

## ✨ Features

- 🔎 **Real-time packet capture** via Scapy (raw sockets, promiscuous mode)
- 🧠 **Banking-aware detection rules** — SYN flood, port scan, DNS tunneling, suspicious User-Agents, and critical banking-port access
- 🔐 **PCI-DSS CDE boundary awareness** — flags external traffic to regulated services
- 📊 **JSON alert logging** — SIEM-ingestible format (`bns_alerts.json`)
- 🛡️ **Optional auto-block** via `iptables` for HIGH and CRITICAL alerts
- 🧩 **Modular design** — capture, parse, detect, and respond as separate layers
- 🌐 **Offline-first** — zero external calls, zero telemetry, zero cloud
- 🐍 **Pure Python** — no C extensions beyond Scapy's libpcap dependency

---

## 🏗️ Architecture

BNS is built as a **four-layer pipeline**. Each layer is a separate module and can be swapped or extended independently.
┌──────────────────────────────────────────────────────────┐
│ Bank Network Sentinel │
├──────────────────────────────────────────────────────────┤
│ │
│ ┌────────────────┐ │
│ │ Capture Layer │ Scapy sniff() — raw sockets │
│ └────────┬───────┘ │
│ │ │
│ ▼ │
│ ┌────────────────┐ │
│ │ Parser Layer │ HTTP / DNS / TCP / UDP dissectors │
│ └────────┬───────┘ │
│ │ │
│ ▼ │
│ ┌────────────────┐ │
│ │ Detection Layer│ Rule engine + ML anomaly (planned) │
│ └────────┬───────┘ │
│ │ │
│ ▼ │
│ ┌────────────────┐ │
│ │ Response Layer │ JSON logs + iptables DROP │
│ └────────────────┘ │
│ │
└──────────────────────────────────────────────────────────┘


### Module Breakdown

| Module | Responsibility |
|--------|----------------|
| `bns/capture.py` | Packet sniffing, queueing, thread management |
| `bns/parser.py` | Protocol dissection, flow tracking, entropy calculation |
| `bns/detector.py` | Rule-based detection engine |
| `bns/response.py` | Alert logging, console output, IP blocking |
| `bns/config.py` | Central configuration (ports, thresholds, features) |
| `bns/main.py` | Orchestration and entry point |

---

## 🚨 Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `SYN_FLOOD` | > 100 SYN packets/sec from one source IP | **HIGH** |
| `PORT_SCAN` | > 15 distinct destination ports from one source | **MEDIUM** |
| `DNS_TUNNEL` | > 50 DNS queries/sec from one host | **HIGH** |
| `SUSPICIOUS_UA` | HTTP User-Agent matches known attack tool signature | **MEDIUM** |
| `EXTERNAL_BANKING_PORT` | External IP → ISO 8583 / SWIFT / CDE port | **CRITICAL** |

### Banking Port Classifications

| Port | Service | Classification |
|------|---------|----------------|
| 443 | HTTPS (banking portal) | Public-facing |
| 8443 | HTTPS (payment gateway) | **CDE — restricted** |
| 9000 | ISO 8583 (card transactions) | **CDE — restricted** |
| 5000 | SWIFT messaging | **Critical infrastructure** |
| 1521 | Oracle DB (core banking) | **Internal only** |
| 3306 | MySQL (transaction logs) | **Internal only** |
| 5432 | PostgreSQL (ledger) | **Internal only** |
| 6379 | Redis (session cache) | **Internal only** |

Access to any **CDE** or **internal-only** port from a non-RFC1918 address triggers `EXTERNAL_BANKING_PORT`.

---

## ⚙️ Installation

### Prerequisites

- **Python** 3.9 or newer
- **libpcap** development headers (for Scapy raw sockets)
- **Root/sudo** access (required for packet capture)
- **Linux** recommended (Kali, Ubuntu, Debian)

### Step 1 — Clone the repository

```bash
git clone https://github.com/meterpreter/bank-network-sentinel.git
cd bank-network-sentinel

Step 2 — Install system dependencies

Debian / Ubuntu / Kali:
bash

sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev

RHEL / Fedora:
bash

sudo dnf install -y python3 python3-pip libpcap-devel

Step 3 — Create a virtual environment
bash

python3 -m venv venv
source venv/bin/activate

Step 4 — Install Python dependencies
bash

pip install -r requirements.txt

Step 5 — Verify installation
bash

python3 -c "import scapy; print('Scapy', scapy.__version__, 'OK')"

🚀 Usage
Basic run
bash

sudo python3 -m bns.main

You should see:


╔══════════════════════════════════════════╗
║   Bank Network Sentinel v1.0            ║
║   Author: meterpreter                    ║
║   Real-time banking network IDS          ║
╚══════════════════════════════════════════╝

[+] Capturing on eth0... (Ctrl+C to stop)

Specify a different interface

Edit bns/config.py:
python

INTERFACE = "wlan0"   # or "eth0", "any"

Or override at runtime (in a future version, --iface CLI flag will be added).
Monitor alerts in real time

In a second terminal:
bash

tail -f bns_alerts.json | jq .

Stop

Press Ctrl+C in the main terminal. BNS shuts down gracefully and flushes remaining queue.
🛠️ Configuration

All tunables live in bns/config.py. Key options:
python

# Interface to sniff on
INTERFACE = "eth0"

# Detection thresholds
SYN_FLOOD_THRESHOLD = 100      # SYN packets per second
PORT_SCAN_THRESHOLD = 15       # distinct ports per source
DNS_TUNNEL_THRESHOLD = 50      # DNS queries per second

# Auto-block HIGH/CRITICAL alerts via iptables (requires root)
AUTO_BLOCK = False

# Alert log file (JSON-lines format, SIEM-ingestible)
LOG_FILE = "bns_alerts.json"

Enabling auto-block

Set AUTO_BLOCK = True in config.py. BNS will add iptables -A INPUT -s <ip> -j DROP rules for every HIGH or CRITICAL alert. Requires root.
Adding a new detection rule

    Open bns/detector.py

    Add a new block inside detect():

python

# --- Rule 6: Your custom rule ---
if rec["proto"] == "tcp" and rec["dport"] == 4444:
    alerts.append({
        "type": "METASPLOIT_DEFAULT_PORT",
        "severity": "HIGH",
        "src": src,
        "port": 4444,
    })

    Restart BNS.

That's it — no DSL, no YAML, no parser. Just Python.
🧪 Testing
Generate benign traffic
bash

curl https://example.com
dig google.com @8.8.8.8 +short

Simulate a port scan
bash

nmap -p 1-100 127.0.0.1

BNS should raise a PORT_SCAN alert after ~15 distinct ports are hit.
Simulate a DNS flood
bash

for i in $(seq 1 60); do dig google.com @8.8.8.8 +short; done

BNS should raise a DNS_TUNNEL alert.
Simulate SYN flood
bash

sudo hping3 -S --flood -p 443 127.0.0.1

BNS should raise a SYN_FLOOD alert.
Check alerts
bash

cat bns_alerts.json | jq '.type, .severity, .src'

🗺️ Roadmap

    ☑

    Real-time packet capture
    ☑

    Banking-port classification
    ☑

    Rule-based detection engine
    ☑

    JSON alert logging
    ☑

    Optional iptables auto-block
    □

    ISO 8583 message parser — dissect card transaction traffic
    □

    ML anomaly detection — Isolation Forest on traffic features
    □

    GeoIP enrichment — MaxMind GeoLite2 tagging for external IPs
    □

    Flask web dashboard — real-time alert visualization
    □

    PCAP export — dump suspicious packets for Wireshark forensics
    □

    SWIFT MT message dissector — parse interbank messaging
    □

    CLI flags — --iface, --config, --no-block overrides
    □

    Docker image — one-command deployment

Want to pick something up? Open an issue and tag it good-first-issue.
🤝 Contributing

Contributions are welcome — especially:

    New banking protocol dissectors (ISO 8583, SWIFT MT, EMV)

    Additional detection rules with clear threat rationale

    ML models and feature engineering

    Documentation and test coverage

How to contribute

    Fork the repo

    Create a feature branch: git checkout -b feature/iso8583-parser

    Commit your changes: git commit -m "Add ISO 8583 dissector"

    Push the branch: git push origin feature/iso8583-parser

    Open a Pull Request

Code style

    PEP 8 compliant

    Docstrings on every public function

    Type hints where practical

    No external network calls in the core pipeline

Testing your changes

Before submitting, verify BNS runs against a loopback interface:
bash

sudo python3 -m bns.main
# In another terminal:
nmap -p 1-50 127.0.0.1

Confirm the expected alert appears in bns_alerts.json.
📄 License

This project is licensed under the MIT License. See the LICENSE file for details.


MIT License

Copyright (c) 2026 meterpreter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

👤 Author

meterpreter

    GitHub: @meterpreter

    Project: Bank Network Sentinel

    "Understand the attacker, build the defender."

🙏 Acknowledgements

BNS draws inspiration from the open-source security community:

    Scapy — packet manipulation framework

    SentinelSec — offline-first IDS design philosophy

    Snort and Suricata — rule engine patterns

    Hashcat — rule-based attack concepts

    MITRE ATT&CK — threat taxonomy for rule naming

⚠️ Disclaimer

BNS is intended for authorized security monitoring only. Running this tool on networks you do not own or do not have explicit written permission to monitor may violate local, state, and federal laws.

Use it on:

    Your own lab / home network

    Authorized penetration testing engagements

    CTF environments

    Educational institutions with permission

Never deploy BNS on production banking infrastructure without a formal change-management approval and legal sign-off.
<div align="center">

⭐ If this project helped you, give it a star — it helps others find it.

Built with 🛡️ by meterpreter
</div> ```
Quick Notes on This README

Why this structure works for interviews:

    The Why BNS? comparison table — instantly answers "why didn't you just use Snort?" which is the #1 question you'll get

    Banking port table — makes your domain knowledge visible in 5 seconds

    Detection rules table — reviewers can see exactly what the tool does without reading code

    Architecture diagram — shows you think in layers, not scripts

    Roadmap checkboxes — signals the project is a platform, not a one-off

    Author signature + tagline — gives it identity; "Understand the attacker, build the defender" is quotable

What to customize before pushing:

    Replace github.com/meterpreter/... with your real repo URL if different

    Change the year in the LICENSE to the current year

    If you're not actually publishing to GitHub under the name meterpreter, keep it as the project handle and use your real name in the Author section

Files you should also add when you publish:
File	Purpose
LICENSE	Copy the MIT text from above
.gitignore	Ignore venv/, *.json, __pycache__/, *.pcap
CONTRIBUTING.md	Optional — link from README
docs/architecture.png	Optional — replace ASCII with a rendered diagram

#One-line .gitignore:

venv/
__pycache__/
*.pyc
bns_alerts.json
*.pcap
.env
