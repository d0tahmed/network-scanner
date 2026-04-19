#!/usr/bin/env python3
"""
cli.py — Command-line interface for NetScanX.

Usage examples
--------------
  sudo python cli.py scan                        # device discovery
  sudo python cli.py scan --ports 22,80,443      # discovery + port scan
  sudo python cli.py scan --full                 # discovery + ports + CVE
  sudo python cli.py scan --interface eth0       # specify interface
  sudo python cli.py scan --full --output report.json
  sudo python cli.py serve                       # launch web UI
  sudo python cli.py serve --port 8080 --debug
"""

import argparse
import json
import sys
from datetime import datetime

from config import config
from utils.logger import get_logger

log = get_logger("cli")


# ── Helpers ────────────────────────────────────────────────────────────────

def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _save_output(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    log.info("Results saved to %s", path)


def _print_devices(devices: list):
    print(f"\n{'─'*60}")
    print(f"  {'IP':<18} {'MAC':<20} {'Vendor':<22} Type")
    print(f"{'─'*60}")
    for d in devices:
        gw = " [GW]" if d.get("is_gateway") else ""
        print(f"  {d['ip']:<18} {d['mac']:<20} {d['vendor']:<22} {d['device_type']}{gw}")
    print(f"{'─'*60}")
    print(f"  Total: {len(devices)} devices\n")


def _print_ports(port_scans: list):
    for host in port_scans:
        if not host.get("open_ports"):
            continue
        print(f"\n  {host['ip']}  ({host.get('hostname','?')})")
        for p in host["open_ports"]:
            print(f"    {p['port']}/{p['protocol']:<5}  {p['service']:<15} {p['product']} {p['version']}")


def _print_vulns(vulns: list):
    if not vulns:
        print("  No vulnerabilities found.\n")
        return
    for v in vulns:
        print(f"\n  {v['ip']}  port {v['port']}  ({v['product']} {v['version']})")
        print(f"  Highest severity: {v['highest_severity']}  — {v['total_cves']} CVEs")
        for cve in v["vulnerabilities"][:3]:
            print(f"    {cve['cve_id']}  CVSS {cve['cvss_score']}  {cve['severity']}")
            print(f"      {cve['description'][:120]} …")
            print(f"      {cve['nvd_url']}")


# ── Sub-commands ───────────────────────────────────────────────────────────

def cmd_scan(args):
    """Run network discovery, optionally followed by port + CVE scans."""
    from scanner import NetworkScanner
    from port_scanner import PortScanner
    from vulnerability_checker import VulnerabilityChecker

    report = {
        "scan_time": _timestamp(),
        "devices":   [],
        "port_scans": [],
        "vulnerabilities": [],
    }

    # ── Step 1: device discovery ──────────────────────────────────────────
    print("\n[*] Scanning network …")
    scanner = NetworkScanner()
    devices = scanner.scan_network(interface=args.interface)
    report["devices"] = devices
    _print_devices(devices)

    if not devices:
        print("[!] No devices found. Are you running as root?")
        sys.exit(1)

    # ── Step 2: port scan ─────────────────────────────────────────────────
    if args.ports or args.full:
        print("[*] Scanning ports …")
        ps      = PortScanner()
        ports   = args.ports or config.default_ports
        results = ps.scan_multiple_hosts([d["ip"] for d in devices])
        report["port_scans"] = results
        _print_ports(results)

        # ── Step 3: CVE lookup ─────────────────────────────────────────────
        if args.full:
            print("[*] Checking CVEs …")
            checker  = VulnerabilityChecker()
            dm       = {d["ip"]: d for d in devices}
            vulns    = []
            for scan in results:
                ip     = scan.get("ip", "?")
                device = dm.get(ip, {})
                for port_info in scan.get("open_ports", []):
                    r = checker.check_port_vulnerabilities(port_info)
                    if r.get("vulnerabilities"):
                        vulns.append({"ip": ip, "hostname": device.get("hostname", "?"), **r})
            report["vulnerabilities"] = vulns
            _print_vulns(vulns)

    if args.output:
        _save_output(report, args.output)


def cmd_serve(args):
    """Launch the Flask web dashboard."""
    # Override config for this run
    config.flask_port  = args.port  or config.flask_port
    config.flask_debug = args.debug or config.flask_debug

    from web_interface import app
    print(f"\n[*] Starting NetScanX dashboard on http://0.0.0.0:{config.flask_port}")
    app.run(host="0.0.0.0", port=config.flask_port,
            debug=config.flask_debug, use_reloader=False)


# ── Argument parsing ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscanx",
        description="NetScanX — Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Run a network scan")
    scan_p.add_argument("-i", "--interface", metavar="IFACE",
                        help="Network interface to use (e.g. eth0, wlan0)")
    scan_p.add_argument("-p", "--ports", metavar="PORTS",
                        help="Comma-separated ports / range to scan")
    scan_p.add_argument("--full", action="store_true",
                        help="Run device + port + CVE scan")
    scan_p.add_argument("-o", "--output", metavar="FILE",
                        help="Save results to JSON file")

    # serve
    serve_p = sub.add_parser("serve", help="Launch the web UI")
    serve_p.add_argument("--port", type=int, help="Port (default: 5000)")
    serve_p.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()