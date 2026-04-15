# 🛡️ NetScan — Network Security Scanner

A local-network security scanner with a web UI. Discovers devices via ARP, scans open ports with nmap, and cross-references detected services against the NVD CVE database to surface known vulnerabilities — all from a single browser tab.

> ⚠️ **For authorized use only.**  
> Only scan networks you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most countries.

---

## Features

- **Device Discovery** — multi-method ARP scanning (scapy + arp-scan tool + system ARP cache) with automatic deduplication and MAC vendor lookup
- **Port Scanning** — nmap `-sV -sC` service/version detection across common ports
- **CVE Lookup** — queries the [NVD REST API](https://nvd.nist.gov/developers/vulnerabilities) for CVEs matching each detected service, with CVSS scoring and severity badges
- **Web UI** — GitHub-dark themed dashboard with sidebar navigation, live activity log, and one-click JSON export
- **XSS-safe** — all external data (hostnames, CVE descriptions, vendor names) is HTML-escaped before rendering

---

## Requirements

| Requirement | Notes |
|---|---|
| OS | Linux (tested on Kali Linux) |
| Python | 3.8+ |
| nmap | `sudo apt install nmap` |
| arp-scan | `sudo apt install arp-scan` |
| Root / sudo | Required for ARP and nmap raw-socket operations |

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/d0tahmed/netscan.git
cd netscan

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install system tools if not already present
sudo apt update && sudo apt install -y nmap arp-scan
```

---

## Usage

```bash
sudo python3 web_interface.py
```

Then open **http://localhost:5000** in your browser.

> `sudo` is required because ARP scanning and nmap SYN scans need raw socket access.

### Scan workflow

1. **Quick Scan** (~30 s) — discovers all devices on your local network
2. **Port Scan** (~2–5 min) — runs nmap on every discovered device
3. **CVE Lookup** (~5–10 min) — checks NVD for each detected service
4. **Full Scan** — runs all three steps automatically in sequence

---

## Project Structure

```
netscan/
├── web_interface.py        # Flask server + API routes
├── scanner.py              # Multi-method ARP device discovery
├── port_scanner.py         # Thread-safe nmap wrapper
├── vulnerability_checker.py# NVD CVE API client with caching
├── templates/
│   └── report.html         # Single-page web UI
├── requirements.txt
└── README.md
```

> **Note:** Flask looks for templates in a `templates/` folder.  
> Move `report.html` there, or adjust the `template_folder` argument in `web_interface.py`.

---

## Screenshots

> *(Add a screenshot of the dashboard here)*

---

## Known Limitations

- Scanning large subnets (e.g. `/16`) can be very slow; designed for home/lab `/24` networks
- NVD CVE lookups are rate-limited to 5 requests per 30 seconds without an API key — add one via `NVDAPIKEY` env var if you hit 403 errors frequently
- Stealth/evasion is not a goal; this is a defender/auditor tool, not an offensive one

---

## Legal Disclaimer

This tool is intended for **educational purposes** and **authorized security auditing only**.  
The author is not responsible for any misuse or damage caused by this software.  
Always obtain proper authorization before scanning any network or device.

---

## Author

Built by a junior cybersecurity red-teamer learning the craft. Contributions and feedback welcome via Issues and Pull Requests.
