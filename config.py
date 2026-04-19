"""
config.py — Centralized configuration for NetScanX
All settings can be overridden via environment variables or a .env file.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

# ── Try loading a .env file if python-dotenv is installed ──────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class ScanConfig:
    # ── Network scanner ────────────────────────────────────────────────────
    arp_timeout:       float = float(os.getenv("ARP_TIMEOUT", "3"))
    ping_timeout:      int   = int(os.getenv("PING_TIMEOUT", "60"))
    max_scan_workers:  int   = int(os.getenv("MAX_SCAN_WORKERS", "5"))

    # ── Port scanner ───────────────────────────────────────────────────────
    default_ports: str = os.getenv(
        "DEFAULT_PORTS",
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    )
    nmap_arguments: str = os.getenv("NMAP_ARGUMENTS", "-sV -sC -T4")

    # ── NVD / CVE ─────────────────────────────────────────────────────────
    nvd_api_key:      Optional[str] = os.getenv("NVD_API_KEY")          # optional
    nvd_api_url:      str           = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_results_page: int           = int(os.getenv("NVD_RESULTS_PAGE", "5"))
    # Without key: 5 req/30 s → 6 s sleep; with key: 50 req/30 s → 0.6 s
    nvd_sleep:        float         = field(init=False)

    # ── Flask ──────────────────────────────────────────────────────────────
    flask_host:   str  = os.getenv("FLASK_HOST", "0.0.0.0")
    flask_port:   int  = int(os.getenv("FLASK_PORT", "5000"))
    flask_debug:  bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    secret_key:   str  = os.getenv("SECRET_KEY", os.urandom(32).hex())

    # ── Logging ────────────────────────────────────────────────────────────
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file:  Optional[str] = os.getenv("LOG_FILE")   # None → stderr only

    def __post_init__(self):
        self.nvd_sleep = 0.6 if self.nvd_api_key else 6.0


# Singleton instance used across all modules
config = ScanConfig()