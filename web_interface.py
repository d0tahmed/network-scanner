#!/usr/bin/env python3
"""
web_interface.py — Flask REST API + web UI for NetScanX.

Endpoints
---------
GET  /                 → Serve the dashboard HTML
GET  /ping             → Health check
POST /api/quick-scan   → Device discovery only
POST /api/port-scan    → Port scan on discovered devices
POST /api/cve-scan     → CVE lookup for discovered services
POST /api/full-scan    → All three steps in sequence
GET  /api/results      → Return current scan_data JSON
GET  /api/export       → Download scan_data as a JSON file
POST /api/clear        → Reset scan_data
"""

import json
import threading
import traceback
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request

from config import config
from port_scanner import PortScanner
from scanner import NetworkScanner
from utils.logger import get_logger
from vulnerability_checker import VulnerabilityChecker

log = get_logger("web")

# ── App init ───────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["SECRET_KEY"]     = config.secret_key

# ── Shared state (protected by a lock) ────────────────────────────────────

_lock = threading.Lock()

_empty_state = lambda: {          # noqa: E731
    "devices":         [],
    "port_scans":      [],
    "vulnerabilities": [],
    "timestamp":       None,
    "status":          "idle",
}

scan_data = _empty_state()


def _update_state(**kwargs):
    """Thread-safe partial update of scan_data."""
    with _lock:
        scan_data.update(kwargs)


def _get_state() -> dict:
    """Thread-safe snapshot of scan_data."""
    with _lock:
        return dict(scan_data)


# ── Helpers ────────────────────────────────────────────────────────────────

def _device_map() -> dict:
    """Return {ip: device_dict} for the current scan_data."""
    with _lock:
        return {d["ip"]: d for d in scan_data["devices"]}


def _enrich_vulns(port_results: list, checker: VulnerabilityChecker) -> list:
    """
    Cross-reference port scan results with discovered devices and
    run CVE checks on every open service.
    """
    dm      = _device_map()
    results = []
    for scan in port_results:
        ip     = scan.get("ip", "Unknown")
        device = dm.get(ip, {})
        for port_info in scan.get("open_ports", []):
            log.info("CVE check — %s port %s", ip, port_info.get("port"))
            result = checker.check_port_vulnerabilities(port_info)
            if result.get("vulnerabilities"):
                results.append({
                    "ip":       ip,
                    "hostname": device.get("hostname", "Unknown"),
                    **result,
                })
    return results


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("report.html")


@app.route("/ping")
def ping():
    return jsonify({"status": "ok", "message": "NetScanX is running"})


@app.route("/api/quick-scan", methods=["POST"])
def quick_scan():
    """Device discovery — fast, no port scanning."""
    _update_state(status="scanning")
    try:
        log.info("Quick scan started.")
        scanner = NetworkScanner()
        devices = scanner.scan_network()
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        _update_state(devices=devices, timestamp=ts, status="done")
        log.info("Quick scan done — %d devices.", len(devices))

        return jsonify({"success": True, "devices": devices,
                        "count": len(devices), "timestamp": ts})
    except Exception as exc:
        _update_state(status="error")
        log.error("Quick scan error: %s\n%s", exc, traceback.format_exc())
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/port-scan", methods=["POST"])
def port_scan():
    """Port scan all previously discovered devices."""
    state = _get_state()
    if not state["devices"]:
        return jsonify({"success": False,
                        "error": "No devices found — run Quick Scan first."}), 400

    try:
        log.info("Port scan started on %d devices.", len(state["devices"]))
        scanner = PortScanner()
        results = scanner.scan_multiple_hosts([d["ip"] for d in state["devices"]])
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        _update_state(port_scans=results, timestamp=ts)
        log.info("Port scan done.")

        return jsonify({"success": True, "port_scans": results, "timestamp": ts})
    except Exception as exc:
        log.error("Port scan error: %s\n%s", exc, traceback.format_exc())
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/cve-scan", methods=["POST"])
def cve_scan():
    """CVE lookup for previously scanned services."""
    state = _get_state()
    if not state["port_scans"]:
        return jsonify({"success": False,
                        "error": "No port scan data — run Port Scan first."}), 400

    try:
        log.info("CVE scan started.")
        checker      = VulnerabilityChecker()
        vuln_results = _enrich_vulns(state["port_scans"], checker)

        _update_state(vulnerabilities=vuln_results)
        log.info("CVE scan done — %d vulnerable services.", len(vuln_results))

        return jsonify({"success": True, "vulnerabilities": vuln_results,
                        "total": len(vuln_results)})
    except Exception as exc:
        log.error("CVE scan error: %s\n%s", exc, traceback.format_exc())
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/full-scan", methods=["POST"])
def full_scan():
    """Device discovery → port scan → CVE lookup in one request."""
    _update_state(status="scanning")
    try:
        # Step 1
        log.info("[1/3] Device discovery …")
        net_scanner = NetworkScanner()
        devices     = net_scanner.scan_network()
        _update_state(devices=devices)
        log.info("  → %d devices found.", len(devices))

        # Step 2
        log.info("[2/3] Port scanning …")
        port_scanner = PortScanner()
        port_results = port_scanner.scan_multiple_hosts([d["ip"] for d in devices])
        _update_state(port_scans=port_results)

        # Step 3
        log.info("[3/3] CVE lookup …")
        checker      = VulnerabilityChecker()
        vuln_results = _enrich_vulns(port_results, checker)

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _update_state(vulnerabilities=vuln_results, timestamp=ts, status="done")

        return jsonify({
            "success":         True,
            "devices":         devices,
            "port_scans":      port_results,
            "vulnerabilities": vuln_results,
            "timestamp":       ts,
        })
    except Exception as exc:
        _update_state(status="error")
        log.error("Full scan error: %s\n%s", exc, traceback.format_exc())
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/results")
def get_results():
    return jsonify(_get_state())


@app.route("/api/export")
def export_results():
    filename = f"netscanx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        json.dumps(_get_state(), indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/clear", methods=["POST"])
def clear_results():
    global scan_data
    with _lock:
        scan_data = _empty_state()
    log.info("Scan data cleared.")
    return jsonify({"success": True})


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("=" * 50)
    log.info("  NetScanX — Network Security Scanner v2")
    log.info("  Dashboard: http://%s:%s", config.flask_host, config.flask_port)
    log.info("=" * 50)
    app.run(
        host=config.flask_host,
        port=config.flask_port,
        debug=config.flask_debug,
        use_reloader=False,
    )