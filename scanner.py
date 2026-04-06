#!/usr/bin/env python3
import scapy.all as scapy
import netifaces
import socket
import subprocess
import re
from mac_vendor_lookup import MacLookup
from typing import List, Dict
import concurrent.futures
import os

class NetworkScanner:
    def __init__(self):
        print("[*] Initializing MAC vendor database...")
        self.mac_lookup = MacLookup()
        try:
            self.mac_lookup.update_vendors()
        except:
            print("[!] Could not update vendor database, using cached version")

    def get_all_interfaces(self) -> List[str]:
        """Get all active network interfaces"""
        interfaces = []
        for iface in netifaces.interfaces():
            if iface == 'lo':
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                interfaces.append(iface)
        return interfaces

    def get_default_gateway(self) -> str:
        """Get the default gateway IP"""
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][0]
        except:
            return None

    def get_network_range(self, interface: str = None) -> str:
        """Get network range from interface"""
        try:
            if interface is None:
                interfaces = self.get_all_interfaces()
                if not interfaces:
                    return "192.168.1.0/24"
                interface = interfaces[0]

            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']

                ip_parts = list(map(int, ip.split('.')))
                mask_parts = list(map(int, netmask.split('.')))
                network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]

                cidr = sum(bin(x).count('1') for x in mask_parts)
                network = '.'.join(map(str, network_parts)) + f'/{cidr}'
                return network
        except Exception as e:
            print(f"[!] Error getting network range: {e}")
            return "192.168.1.0/24"

    def arp_scan(self, ip_range: str, interface: str = None) -> List[Dict]:
        """Perform ARP scan - primary method"""
        devices = []
        try:
            print(f"[*] ARP scanning: {ip_range}")

            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            kwargs = {"timeout": 3, "verbose": False}
            if interface:
                kwargs["iface"] = interface

            answered_list = scapy.srp(arp_request_broadcast, **kwargs)[0]

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                devices.append({'ip': ip, 'mac': mac, 'source': 'arp_scapy'})
                print(f"[+] ARP found: {ip} -> {mac}")

        except Exception as e:
            print(f"[!] ARP scan error: {e}")

        return devices

    def arp_scan_tool(self, interface: str = None) -> List[Dict]:
        """Use arp-scan tool as backup"""
        devices = []
        try:
            cmd = ["sudo", "arp-scan", "--localnet"]
            if interface:
                cmd += ["-I", interface]

            print("[*] Running arp-scan tool...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'

                    ip_match = re.search(ip_pattern, parts[0])
                    mac_match = re.search(mac_pattern, parts[1])

                    if ip_match and mac_match:
                        devices.append({
                            'ip': ip_match.group(),
                            'mac': mac_match.group(),
                            'source': 'arp_tool'
                        })
                        print(f"[+] arp-scan found: {ip_match.group()} -> {mac_match.group()}")

        except FileNotFoundError:
            print("[!] arp-scan not installed. Run: sudo apt install arp-scan")
        except Exception as e:
            print(f"[!] arp-scan tool error: {e}")

        return devices

    def read_arp_cache(self) -> List[Dict]:
        """Read system ARP cache"""
        devices = []
        try:
            print("[*] Reading ARP cache...")
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            for line in result.stdout.splitlines():
                ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)

                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(0)

                    if mac != '00:00:00:00:00:00' and '<incomplete>' not in line:
                        devices.append({'ip': ip, 'mac': mac, 'source': 'arp_cache'})
                        print(f"[+] ARP cache: {ip} -> {mac}")

        except Exception as e:
            print(f"[!] ARP cache error: {e}")

        return devices

    def ping_sweep(self, ip_range: str) -> List[str]:
        """Ping sweep to wake up devices before ARP scan"""
        active_ips = []
        try:
            print(f"[*] Ping sweeping {ip_range} to wake up devices...")

            result = subprocess.run(
                ['sudo', 'nmap', '-sn', '-T4', ip_range],
                capture_output=True, text=True, timeout=60
            )

            for line in result.stdout.splitlines():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match and 'Nmap scan report' in line:
                    active_ips.append(ip_match.group(1))
                    print(f"[+] Ping found active: {ip_match.group(1)}")

        except Exception as e:
            print(f"[!] Ping sweep error: {e}")

        return active_ips

    def get_vendor(self, mac: str) -> str:
        """Get vendor from MAC address"""
        try:
            return self.mac_lookup.lookup(mac)
        except:
            prefix = mac.upper().replace('-', ':')[:8]
            common_vendors = {
                'AC:84:C6': 'Apple Inc',
                'B8:27:EB': 'Raspberry Pi Foundation',
                'DC:A6:32': 'Raspberry Pi Foundation',
                'FC:AA:14': 'Amazon Technologies',
                '00:0C:29': 'VMware Inc',
                '00:50:56': 'VMware Inc',
                'A4:C3:F0': 'Google LLC',
                '40:4E:36': 'Samsung Electronics',
                '00:1A:2B': 'Unknown Device',
            }
            return common_vendors.get(prefix, "Unknown Vendor")

    def get_hostname(self, ip: str) -> str:
        """Get hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def get_device_type(self, vendor: str, open_ports: List = None) -> str:
        """Guess device type from vendor name"""
        vendor_lower = vendor.lower()

        if any(x in vendor_lower for x in ['apple', 'iphone', 'ipad']):
            return "Apple Device (iPhone/iPad/Mac)"
        elif any(x in vendor_lower for x in ['samsung', 'huawei', 'xiaomi', 'oneplus']):
            return "Android/Mobile Device"
        elif any(x in vendor_lower for x in ['tp-link', 'netgear', 'asus', 'linksys', 'dlink', 'd-link', 'cisco']):
            return "Router/Network Device"
        elif any(x in vendor_lower for x in ['raspberry']):
            return "Raspberry Pi"
        elif any(x in vendor_lower for x in ['vmware', 'virtualbox', 'parallels']):
            return "Virtual Machine"
        elif any(x in vendor_lower for x in ['intel', 'realtek', 'broadcom']):
            return "PC/Laptop"
        elif any(x in vendor_lower for x in ['amazon', 'google', 'roku']):
            return "Smart Device/TV"
        else:
            return "Unknown Device"

    def _is_real_mac(self, mac: str) -> bool:
        """Return True if MAC looks like a real unicast hardware address (not broadcast/multicast)."""
        if not mac or mac == 'Unknown':
            return False
        # Multicast bit: first octet LSB == 1
        first_octet = int(mac.replace(':', '').replace('-', '')[:2], 16)
        return (first_octet & 0x01) == 0

    def scan_network(self, interface: str = None) -> List[Dict]:
        """Main scan function - uses multiple methods to find ALL devices"""
        gateway = self.get_default_gateway()

        if interface is None:
            interfaces = self.get_all_interfaces()
            interface = interfaces[0] if interfaces else None

        ip_range = self.get_network_range(interface)
        print(f"\n[*] Interface: {interface}")
        print(f"[*] Network range: {ip_range}")
        print(f"[*] Gateway: {gateway}")
        print("[*] Using multiple scan methods...\n")

        # Step 1: Ping sweep to wake devices
        self.ping_sweep(ip_range)

        # Step 2: Gather results from all three ARP methods
        arp_devices    = self.arp_scan(ip_range, interface)
        arptool_devices = self.arp_scan_tool(interface)
        cache_devices  = self.read_arp_cache()

        # --- Deduplicate by IP, prefer real unicast MACs over fallbacks ---
        # Priority: scapy ARP > arp-scan tool > arp cache
        all_devices_raw: Dict[str, Dict] = {}

        source_priority = {'arp_scapy': 3, 'arp_tool': 2, 'arp_cache': 1}

        for device in arp_devices + arptool_devices + cache_devices:
            ip  = device['ip']
            mac = device.get('mac', 'Unknown')
            src = device.get('source', 'arp_cache')

            if ip not in all_devices_raw:
                all_devices_raw[ip] = device
            else:
                existing     = all_devices_raw[ip]
                existing_mac = existing.get('mac', 'Unknown')
                existing_pri = source_priority.get(existing.get('source', ''), 0)
                new_pri      = source_priority.get(src, 0)

                # Replace if: new MAC is "more real" or from a higher-priority source
                existing_real = self._is_real_mac(existing_mac)
                new_real      = self._is_real_mac(mac)

                if (not existing_real and new_real) or \
                   (existing_real == new_real and new_pri > existing_pri):
                    print(f"[~] Dedup {ip}: replacing MAC {existing_mac} "
                          f"({existing.get('source')}) with {mac} ({src})")
                    all_devices_raw[ip] = device

        # --- Enrich device info ---
        final_devices = []
        for ip, device in all_devices_raw.items():
            mac         = device.get('mac', 'Unknown')
            vendor      = self.get_vendor(mac)
            hostname    = self.get_hostname(ip)
            is_gateway  = (ip == gateway)
            device_type = self.get_device_type(vendor)

            enriched = {
                'ip':          ip,
                'mac':         mac,
                'vendor':      vendor,
                'hostname':    hostname,
                'device_type': device_type,
                'is_gateway':  is_gateway,
                'status':      'Online'
            }
            final_devices.append(enriched)

            print(f"\n{'='*50}")
            print(f"  IP       : {ip}")
            print(f"  MAC      : {mac}")
            print(f"  Vendor   : {vendor}")
            print(f"  Hostname : {hostname}")
            print(f"  Type     : {device_type}")
            print(f"  Gateway  : {is_gateway}")
            print(f"{'='*50}")

        print(f"\n[+] Total devices found: {len(final_devices)}")
        return final_devices


if __name__ == "__main__":
    scanner = NetworkScanner()
    devices = scanner.scan_network()