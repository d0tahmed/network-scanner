#!/usr/bin/env python3
"""
scanner.py — Layer-2/3 network discovery for NetScanX.

Uses three complementary methods (Scapy ARP, arp-scan CLI, system ARP
cache) and merges results with a source-priority deduplication strategy.
"""

import re
import socket
import subprocess
from typing import Dict, List, Optional

import netifaces
import scapy.all as scapy
from mac_vendor_lookup import MacLookup

from config import config
from utils.logger import get_logger

log = get_logger("scanner")


class NetworkScanner:
    """Discover all live hosts on the local network."""

    def __init__(self):
        log.info("Initialising MAC vendor database …")
        self.mac_lookup = MacLookup()
        try:
            self.mac_lookup.update_vendors()
            log.info("MAC vendor database updated successfully.")
        except Exception as exc:
            log.warning("Could not update vendor database (%s). Using cached copy.", exc)

    # ── Interface helpers ──────────────────────────────────────────────────

    def get_all_interfaces(self) -> List[str]:
        """Return all active (non-loopback) IPv4-capable interface names."""
        ifaces = []
        for iface in netifaces.interfaces():
            if iface == "lo":
                continue
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                ifaces.append(iface)
        return ifaces

    def get_default_gateway(self) -> Optional[str]:
        """Return the default gateway IP, or None if unavailable."""
        try:
            return netifaces.gateways()["default"][netifaces.AF_INET][0]
        except (KeyError, IndexError):
            log.warning("Could not determine default gateway.")
            return None

    def get_network_range(self, interface: Optional[str] = None) -> str:
        """Derive the CIDR network range for *interface* (auto-detected if None)."""
        try:
            if interface is None:
                ifaces = self.get_all_interfaces()
                interface = ifaces[0] if ifaces else None

            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip      = addrs[netifaces.AF_INET][0]["addr"]
                netmask = addrs[netifaces.AF_INET][0]["netmask"]

                ip_parts   = list(map(int, ip.split(".")))
                mask_parts = list(map(int, netmask.split(".")))
                net_parts  = [ip_parts[i] & mask_parts[i] for i in range(4)]
                cidr       = sum(bin(x).count("1") for x in mask_parts)
                return ".".join(map(str, net_parts)) + f"/{cidr}"
        except Exception as exc:
            log.error("Error deriving network range: %s", exc)
        return "192.168.1.0/24"

    # ── Scan methods ───────────────────────────────────────────────────────

    def arp_scan(self, ip_range: str, interface: Optional[str] = None) -> List[Dict]:
        """Primary ARP scan via Scapy."""
        devices: List[Dict] = []
        log.info("ARP scanning %s …", ip_range)
        try:
            pkt    = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range)
            kwargs: Dict = {"timeout": config.arp_timeout, "verbose": False}
            if interface:
                kwargs["iface"] = interface

            answered = scapy.srp(pkt, **kwargs)[0]
            for _, resp in answered:
                ip, mac = resp.psrc, resp.hwsrc
                devices.append({"ip": ip, "mac": mac, "source": "arp_scapy"})
                log.debug("ARP found: %s → %s", ip, mac)
        except Exception as exc:
            log.error("Scapy ARP scan error: %s", exc)
        return devices

    def arp_scan_tool(self, interface: Optional[str] = None) -> List[Dict]:
        """Fallback: use the arp-scan CLI tool."""
        devices: List[Dict] = []
        try:
            cmd = ["sudo", "arp-scan", "--localnet"]
            if interface:
                cmd += ["-I", interface]
            log.info("Running arp-scan CLI …")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            ip_re  = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
            mac_re = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")

            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                ip_m  = ip_re.search(parts[0])
                mac_m = mac_re.search(parts[1])
                if ip_m and mac_m:
                    devices.append({"ip": ip_m.group(), "mac": mac_m.group(), "source": "arp_tool"})
                    log.debug("arp-scan found: %s → %s", ip_m.group(), mac_m.group())
        except FileNotFoundError:
            log.warning("arp-scan not installed. Run: sudo apt install arp-scan")
        except Exception as exc:
            log.error("arp-scan tool error: %s", exc)
        return devices

    def read_arp_cache(self) -> List[Dict]:
        """Read the OS ARP cache as a last-resort fallback."""
        devices: List[Dict] = []
        log.info("Reading system ARP cache …")
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            ip_re  = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)")
            mac_re = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")

            for line in result.stdout.splitlines():
                ip_m  = ip_re.search(line)
                mac_m = mac_re.search(line)
                if ip_m and mac_m:
                    mac = mac_m.group(0)
                    if mac != "00:00:00:00:00:00" and "<incomplete>" not in line:
                        devices.append({"ip": ip_m.group(1), "mac": mac, "source": "arp_cache"})
                        log.debug("ARP cache: %s → %s", ip_m.group(1), mac)
        except Exception as exc:
            log.error("ARP cache read error: %s", exc)
        return devices

    def ping_sweep(self, ip_range: str) -> List[str]:
        """Nmap ping sweep to wake sleeping devices before ARP scans."""
        active: List[str] = []
        log.info("Ping-sweeping %s …", ip_range)
        try:
            result = subprocess.run(
                ["sudo", "nmap", "-sn", "-T4", ip_range],
                capture_output=True, text=True, timeout=config.ping_timeout,
            )
            ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
            for line in result.stdout.splitlines():
                if "Nmap scan report" in line:
                    m = ip_re.search(line)
                    if m:
                        active.append(m.group(1))
                        log.debug("Ping active: %s", m.group(1))
        except Exception as exc:
            log.error("Ping sweep error: %s", exc)
        return active

    # ── Enrichment helpers ─────────────────────────────────────────────────

    def get_vendor(self, mac: str) -> str:
        """Resolve a MAC prefix to a vendor name."""
        try:
            return self.mac_lookup.lookup(mac)
        except Exception:
            prefix = mac.upper().replace("-", ":")[:8]
            fallback = {
                "AC:84:C6": "Apple Inc",
                "B8:27:EB": "Raspberry Pi Foundation",
                "DC:A6:32": "Raspberry Pi Foundation",
                "FC:AA:14": "Amazon Technologies",
                "00:0C:29": "VMware Inc",
                "00:50:56": "VMware Inc",
                "A4:C3:F0": "Google LLC",
                "40:4E:36": "Samsung Electronics",
            }
            return fallback.get(prefix, "Unknown Vendor")

    def get_hostname(self, ip: str) -> str:
        """Reverse-DNS lookup for an IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

    def get_device_type(self, vendor: str) -> str:
        """Classify device type from vendor string."""
        v = vendor.lower()
        checks = [
            (["apple", "iphone", "ipad"],                        "Apple Device"),
            (["samsung", "huawei", "xiaomi", "oneplus"],         "Android / Mobile"),
            (["tp-link", "netgear", "asus", "linksys",
              "dlink", "d-link", "cisco", "ubiquiti"],           "Router / Network Device"),
            (["raspberry"],                                        "Raspberry Pi"),
            (["vmware", "virtualbox", "parallels"],               "Virtual Machine"),
            (["intel", "realtek", "broadcom"],                    "PC / Laptop"),
            (["amazon", "google", "roku"],                        "Smart Device / TV"),
            (["hp", "hewlett"],                                   "HP Device"),
            (["dell", "lenovo", "acer"],                          "PC / Laptop"),
        ]
        for keywords, label in checks:
            if any(k in v for k in keywords):
                return label
        return "Unknown Device"

    @staticmethod
    def _is_real_mac(mac: str) -> bool:
        """Return True for a unicast (non-broadcast, non-multicast) MAC."""
        if not mac or mac == "Unknown":
            return False
        try:
            first = int(mac.replace(":", "").replace("-", "")[:2], 16)
            return (first & 0x01) == 0
        except ValueError:
            return False

    # ── Main scan ──────────────────────────────────────────────────────────

    def scan_network(self, interface: Optional[str] = None) -> List[Dict]:
        """
        Discover all live hosts.

        Runs three discovery methods, deduplicates by IP (preferring real
        unicast MACs and higher-priority sources), then enriches each entry
        with vendor, hostname, and device-type data.
        """
        gateway = self.get_default_gateway()

        if interface is None:
            ifaces    = self.get_all_interfaces()
            interface = ifaces[0] if ifaces else None

        ip_range = self.get_network_range(interface)
        log.info("Interface: %s | Network: %s | Gateway: %s", interface, ip_range, gateway)

        self.ping_sweep(ip_range)

        raw: Dict[str, Dict] = {}
        priority = {"arp_scapy": 3, "arp_tool": 2, "arp_cache": 1}

        for device in (
            self.arp_scan(ip_range, interface)
            + self.arp_scan_tool(interface)
            + self.read_arp_cache()
        ):
            ip  = device["ip"]
            mac = device.get("mac", "Unknown")
            src = device.get("source", "arp_cache")

            if ip not in raw:
                raw[ip] = device
            else:
                existing = raw[ip]
                ex_real  = self._is_real_mac(existing.get("mac", ""))
                new_real = self._is_real_mac(mac)
                ex_pri   = priority.get(existing.get("source", ""), 0)
                new_pri  = priority.get(src, 0)

                if (not ex_real and new_real) or (ex_real == new_real and new_pri > ex_pri):
                    log.debug("Dedup %s: %s (%s) → %s (%s)",
                              ip, existing.get("mac"), existing.get("source"), mac, src)
                    raw[ip] = device

        devices: List[Dict] = []
        for ip, device in raw.items():
            mac    = device.get("mac", "Unknown")
            vendor = self.get_vendor(mac)
            entry  = {
                "ip":          ip,
                "mac":         mac,
                "vendor":      vendor,
                "hostname":    self.get_hostname(ip),
                "device_type": self.get_device_type(vendor),
                "is_gateway":  ip == gateway,
                "status":      "Online",
            }
            devices.append(entry)
            log.info("Found  %-16s  %-20s  %s", ip, mac, vendor)

        log.info("Total devices found: %d", len(devices))
        return devices


if __name__ == "__main__":
    scanner = NetworkScanner()
    results = scanner.scan_network()