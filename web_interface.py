#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, Response
from scanner import NetworkScanner
from port_scanner import PortScanner
from vulnerability_checker import VulnerabilityChecker
from datetime import datetime
import json
import traceback

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global storage
scan_data = {
    'devices':         [],
    'port_scans':      [],
    'vulnerabilities': [],
    'timestamp':       None,
    'status':          'idle'
}

# ─────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────

@app.route('/')
def index():
    return render_template('report.html')


@app.route('/ping')
def ping():
    """Test if server is alive"""
    return jsonify({'status': 'ok', 'message': 'Server is running'})


@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Scan devices only – fast"""
    global scan_data
    scan_data['status'] = 'scanning'

    try:
        print("\n[*] Quick scan started...")
        scanner = NetworkScanner()
        devices = scanner.scan_network()

        scan_data['devices']   = devices
        scan_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_data['status']    = 'done'

        print(f"[+] Quick scan done. Found {len(devices)} devices")

        return jsonify({
            'success':   True,
            'devices':   devices,
            'count':     len(devices),
            'timestamp': scan_data['timestamp']
        })

    except Exception as e:
        scan_data['status'] = 'error'
        error_msg = str(e)
        print(f"[!] Quick scan error: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': error_msg}), 500


@app.route('/api/port-scan', methods=['POST'])
def port_scan():
    """Scan ports on all discovered devices"""
    global scan_data

    if not scan_data['devices']:
        return jsonify({
            'success': False,
            'error':   'No devices found. Run quick scan first.'
        }), 400

    try:
        print("\n[*] Port scan started...")
        scanner = PortScanner()
        results = []

        for device in scan_data['devices']:
            ip = device['ip']
            print(f"[*] Scanning ports on {ip}...")
            result = scanner.scan_ports(ip)
            results.append(result)

        scan_data['port_scans'] = results
        scan_data['timestamp']  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print("[+] Port scan done.")

        return jsonify({
            'success':    True,
            'port_scans': results,
            'timestamp':  scan_data['timestamp']
        })

    except Exception as e:
        error_msg = str(e)
        print(f"[!] Port scan error: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': error_msg}), 500


@app.route('/api/cve-scan', methods=['POST'])
def cve_scan():
    """Check CVEs for discovered services"""
    global scan_data

    if not scan_data['port_scans']:
        return jsonify({
            'success': False,
            'error':   'No port scan data. Run port scan first.'
        }), 400

    try:
        print("\n[*] CVE scan started...")
        checker = VulnerabilityChecker()
        vuln_results = []

        # --- FIX: build an IP-keyed map instead of relying on list index
        #     alignment between port_scans and devices.  If a port scan
        #     fails for one host the two lists go out of sync and the
        #     wrong device metadata is attached to every subsequent entry.
        device_map = {d['ip']: d for d in scan_data['devices']}

        for scan in scan_data['port_scans']:
            ip     = scan.get('ip', 'Unknown')
            device = device_map.get(ip, {})

            for port_info in scan.get('open_ports', []):
                print(f"[*] Checking CVE for {ip} port {port_info.get('port')}...")
                result = checker.check_port_vulnerabilities(port_info)

                if result.get('vulnerabilities'):
                    vuln_results.append({
                        'ip':       ip,
                        'hostname': device.get('hostname', 'Unknown'),
                        **result
                    })

        scan_data['vulnerabilities'] = vuln_results
        print(f"[+] CVE scan done. Found {len(vuln_results)} vulnerable services.")

        return jsonify({
            'success':        True,
            'vulnerabilities': vuln_results,
            'total':          len(vuln_results)
        })

    except Exception as e:
        error_msg = str(e)
        print(f"[!] CVE scan error: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': error_msg}), 500


@app.route('/api/full-scan', methods=['POST'])
def full_scan():
    """Run all scans in sequence"""
    global scan_data
    scan_data['status'] = 'scanning'

    try:
        # Step 1: Device scan
        print("\n[STEP 1/3] Scanning devices...")
        net_scanner = NetworkScanner()
        devices = net_scanner.scan_network()
        scan_data['devices'] = devices
        print(f"[+] Found {len(devices)} devices")

        # Step 2: Port scan
        print("\n[STEP 2/3] Scanning ports...")
        port_scanner = PortScanner()
        port_results = []
        for device in devices:
            result = port_scanner.scan_ports(device['ip'])
            port_results.append(result)
        scan_data['port_scans'] = port_results

        # Step 3: CVE check
        print("\n[STEP 3/3] Checking CVEs...")
        checker    = VulnerabilityChecker()
        vuln_results = []

        # --- FIX: same IP-keyed map used here too ---
        device_map = {d['ip']: d for d in devices}

        for scan in port_results:
            ip     = scan.get('ip', 'Unknown')
            device = device_map.get(ip, {})

            for port_info in scan.get('open_ports', []):
                result = checker.check_port_vulnerabilities(port_info)
                if result.get('vulnerabilities'):
                    vuln_results.append({
                        'ip':       ip,
                        'hostname': device.get('hostname', 'Unknown'),
                        **result
                    })

        scan_data['vulnerabilities'] = vuln_results
        scan_data['timestamp']       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_data['status']          = 'done'

        return jsonify({
            'success':         True,
            'devices':         devices,
            'port_scans':      port_results,
            'vulnerabilities': vuln_results,
            'timestamp':       scan_data['timestamp']
        })

    except Exception as e:
        scan_data['status'] = 'error'
        error_msg = str(e)
        print(f"[!] Full scan error: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': error_msg}), 500


@app.route('/api/results')
def get_results():
    return jsonify(scan_data)


@app.route('/api/export')
def export_results():
    data = json.dumps(scan_data, indent=2)
    return Response(
        data,
        mimetype='application/json',
        headers={
            'Content-Disposition':
                f'attachment; filename=scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        }
    )


@app.route('/api/clear', methods=['POST'])
def clear_results():
    global scan_data
    scan_data = {
        'devices':         [],
        'port_scans':      [],
        'vulnerabilities': [],
        'timestamp':       None,
        'status':          'idle'
    }
    return jsonify({'success': True})


# ─────────────────────────────────────────
#  START
# ─────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 50)
    print("  Network Security Scanner")
    print("  Open: http://localhost:5000")
    print("=" * 50)
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        use_reloader=False   # Prevents double-start issue
    )