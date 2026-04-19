#!/usr/bin/env python3
"""
port_scanner.py — Service/version detection for NetScanX.

Each scan_ports() call creates its own nmap.PortScanner instance so
concurrent calls from ThreadPoolExecutor never share state.
"""

import concurrent.futures
from typing import Dict, List, Optional

import nmap

from config import config
from utils.logger import get_logger

log = get_logger("port_scanner")


class PortScanner:
    """Enumerate open TCP/UDP ports and detect service versions."""

    def __init__(self):
        self.common_ports = config.default_ports
        self.nmap_args    = config.nmap_arguments

    # ── Single-host scan ──────────────────────────────────────────────────

    def scan_ports(
        self,
        ip: str,
        ports: Optional[str] = None,
        arguments: Optional[str] = None,
    ) -> Dict:
        """
        Scan ports on *ip* and return a structured result dict.

        A new nmap.PortScanner() is created per call — never stored on
        self — so concurrent invocations from scan_multiple_hosts() are
        always thread-safe.

        Args:
            ip:        Target IPv4 address.
            ports:     Comma-separated port list or range (default: common ports).
            arguments: Raw nmap arguments string (default: from config).
        """
        ports     = ports     or self.common_ports
        arguments = arguments or self.nmap_args

        log.info("Port scanning %s …", ip)
        nm = nmap.PortScanner()   # thread-local; never shared

        try:
            nm.scan(ip, ports, arguments=arguments)

            result: Dict = {
                "ip":         ip,
                "hostname":   nm[ip].hostname() if ip in nm.all_hosts() else "Unknown",
                "state":      nm[ip].state()    if ip in nm.all_hosts() else "down",
                "open_ports": [],
            }

            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port, info in nm[ip][proto].items():
                        if info["state"] != "open":
                            continue
                        port_data = {
                            "port":      port,
                            "protocol":  proto,
                            "service":   info.get("name",      "unknown"),
                            "version":   info.get("version",   "unknown"),
                            "product":   info.get("product",   "unknown"),
                            "extrainfo": info.get("extrainfo", ""),
                            "cpe":       info.get("cpe",       ""),
                        }
                        result["open_ports"].append(port_data)
                        log.info("  %s  port %s/%s open — %s %s",
                                 ip, port, proto,
                                 port_data["service"], port_data["version"])

            return result

        except Exception as exc:
            log.error("Error scanning %s: %s", ip, exc)
            return {"ip": ip, "error": str(exc), "open_ports": []}

    # ── Multi-host scan ───────────────────────────────────────────────────

    def scan_multiple_hosts(
        self,
        ip_list: List[str],
        max_workers: Optional[int] = None,
    ) -> List[Dict]:
        """
        Scan multiple hosts concurrently.

        Args:
            ip_list:     List of target IPv4 addresses.
            max_workers: Thread pool size (default: from config).
        """
        workers = max_workers or config.max_scan_workers
        results: List[Dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.scan_ports, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    ip = futures[future]
                    log.error("Thread exception for %s: %s", ip, exc)
                    results.append({"ip": ip, "error": str(exc), "open_ports": []})

        return results


if __name__ == "__main__":
    scanner = PortScanner()
    result  = scanner.scan_ports("192.168.1.1")
    print(result)