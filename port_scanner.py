#!/usr/bin/env python3
import nmap
import socket
from typing import List, Dict
import concurrent.futures

class PortScanner:
    def __init__(self):
        # Common ports to scan
        self.common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

    def scan_ports(self, ip: str, ports: str = None, arguments: str = '-sV -sC') -> Dict:
        """
        Scan ports on a target IP.

        A NEW nmap.PortScanner() instance is created for every call so that
        concurrent invocations from scan_multiple_hosts() never share state.
        The original code stored self.nm on the instance, which caused
        data corruption when multiple threads called self.nm.scan() at the
        same time.

        Args:
            ip:        Target IP address
            ports:     Port range (default: common ports)
            arguments: Nmap arguments (-sV for version, -sC for scripts)
        """
        if ports is None:
            ports = self.common_ports

        print(f"[*] Scanning ports on {ip}...")

        # --- FIX: local instance, never shared between threads ---
        nm = nmap.PortScanner()

        try:
            nm.scan(ip, ports, arguments=arguments)

            scan_result = {
                'ip':         ip,
                'hostname':   nm[ip].hostname() if ip in nm.all_hosts() else 'Unknown',
                'state':      nm[ip].state()    if ip in nm.all_hosts() else 'down',
                'open_ports': []
            }

            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    ports_dict = nm[ip][proto]

                    for port, port_info in ports_dict.items():
                        if port_info['state'] == 'open':
                            port_data = {
                                'port':      port,
                                'protocol':  proto,
                                'service':   port_info.get('name',      'unknown'),
                                'version':   port_info.get('version',   'unknown'),
                                'product':   port_info.get('product',   'unknown'),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'cpe':       port_info.get('cpe',       '')
                            }
                            scan_result['open_ports'].append(port_data)
                            print(f"[+] Port {port}/{proto} open – {port_data['service']}")

            return scan_result

        except Exception as e:
            print(f"[!] Error scanning {ip}: {str(e)}")
            return {'ip': ip, 'error': str(e), 'open_ports': []}

    def scan_multiple_hosts(self, ip_list: List[str]) -> List[Dict]:
        """Scan multiple hosts concurrently (thread-safe because each call gets its own nm)."""
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ip = {executor.submit(self.scan_ports, ip): ip for ip in ip_list}

            for future in concurrent.futures.as_completed(future_to_ip):
                results.append(future.result())

        return results


if __name__ == "__main__":
    scanner = PortScanner()
    result = scanner.scan_ports("192.168.1.1")
    print(result)