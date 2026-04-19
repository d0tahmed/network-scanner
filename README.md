# Network-scanner v2🔍

**A professional-grade local network security scanner.**  
Discover devices, enumerate open ports, and check for known CVEs — all from a slick dark web dashboard or a powerful CLI.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red?logo=linux)

> ⚠️ **Legal Notice:** Use NetScanX only on networks you own or have explicit written permission to scan. Unauthorized scanning is illegal under computer misuse laws in most countries.

---

## Features

| Feature | Details |
|---|---|
| 🖥 **Device Discovery** | ARP scan (Scapy), arp-scan CLI, and ARP cache — triple-method deduplication |
| 🔌 **Port Scanning** | Nmap service/version detection with concurrent multi-host support |
| 🛡 **CVE Lookup** | NIST NVD API v2 integration with CVSS v3.1 severity scoring |
| 🌐 **Web Dashboard** | Dark-themed Flask UI with live scan progress and JSON export |
| ⌨️ **CLI Interface** | Full argparse CLI for automation and headless environments |
| 📋 **Logging** | Structured logging to stderr and optional file output |
| ⚙️ **Config** | Environment variable / `.env` based configuration |

---

## Screenshots

> Web dashboard with device discovery, port scan, and CVE results — all in one view.

---

## Quick Start

### 1. System dependencies

```bash
# Debian / Ubuntu / Kali
sudo apt update
sudo apt install nmap arp-scan python3-pip
```

### 2. Python dependencies

```bash
git clone https://github.com/d0tahmed/network-scanner.git
cd netscanx
pip install -r requirements.txt
```

### 3. Optional — NVD API key (recommended)

Register for a free API key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).  
Without a key the scanner is rate-limited to 5 requests per 30 seconds.

```bash
cp .env.example .env
# Edit .env and add your key:
# NVD_API_KEY=your-key-here
```

---

## Usage

### Web Dashboard (recommended)

```bash
sudo python web_interface.py
# Open: http://localhost:5000
```

Then use the buttons in order:

1. **Quick Scan** — find all devices on your network
2. **Port Scan** — enumerate open ports on found devices
3. **CVE Scan** — look up known vulnerabilities for detected services
4. **Full Scan** — run all three steps automatically

### CLI

```bash
# Device discovery only
sudo python cli.py scan

# Discovery + port scan on specific ports
sudo python cli.py scan --ports 22,80,443,8080

# Full scan (device + ports + CVE) saved to file
sudo python cli.py scan --full --output report.json

# Specify a network interface
sudo python cli.py scan --interface wlan0 --full

# Launch web UI on a custom port
sudo python cli.py serve --port 8080
```

---

## Project Structure

```
NETWORK-SCANNER/
├── scanner.py              # Device discovery (ARP + ping sweep)
├── port_scanner.py         # Port/service enumeration (nmap)
├── vulnerability_checker.py # CVE lookup (NIST NVD API)
├── web_interface.py        # Flask REST API + dashboard server
├── cli.py                  # Argparse CLI
├── config.py               # Centralized configuration
├── utils/
│   ├── __init__.py
│   └── logger.py           # Logging setup
├── templates/
│   └── report.html         # Web dashboard UI
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Configuration

All settings can be overridden via environment variables or a `.env` file in the project root.

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | *(none)* | NIST NVD API key (strongly recommended) |
| `DEFAULT_PORTS` | Common 20 ports | Comma-separated ports to scan |
| `NMAP_ARGUMENTS` | `-sV -sC -T4` | Raw nmap flags |
| `ARP_TIMEOUT` | `3` | Scapy ARP timeout (seconds) |
| `MAX_SCAN_WORKERS` | `5` | Concurrent port scan threads |
| `FLASK_HOST` | `0.0.0.0` | Web server bind address |
| `FLASK_PORT` | `5000` | Web server port |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`) |
| `LOG_FILE` | *(none)* | Optional log file path |

---

## API Reference

All scan endpoints accept `POST` with no body required.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard |
| `GET` | `/ping` | Health check |
| `POST` | `/api/quick-scan` | Device discovery |
| `POST` | `/api/port-scan` | Port scan (requires quick-scan first) |
| `POST` | `/api/cve-scan` | CVE lookup (requires port-scan first) |
| `POST` | `/api/full-scan` | All three in sequence |
| `GET` | `/api/results` | Current scan state (JSON) |
| `GET` | `/api/export` | Download results as `.json` |
| `POST` | `/api/clear` | Reset scan state |

---

## Scan Methods

NETWORK-SCANNER uses three ARP discovery methods and picks the best result for each IP:

| Priority | Method | Requires |
|---|---|---|
| 1 (highest) | Scapy ARP broadcast | `root` / `sudo` |
| 2 | `arp-scan` CLI | `arp-scan` package |
| 3 | System ARP cache | Always available |

A ping sweep (`nmap -sn`) is run first to wake devices that might not respond to ARP alone.

---

## Requirements

- Python 3.10+
- Linux (Kali, Ubuntu, Debian)
- `nmap` installed (`sudo apt install nmap`)
- Run as `root` / `sudo` (required for raw packet operations)

---

## Disclaimer

NETWORK-SCANNER is an educational and authorized-use security tool. The author is not responsible for misuse. Always obtain proper authorization before scanning any network.

---

## License

MIT — see [LICENSE](LICENSE) for details.