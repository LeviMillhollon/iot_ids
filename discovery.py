"""
discovery.py

Handles raw network discovery and data collection:

- Figures out the local subnet and interface info
- Uses ARP to discover live hosts (no ping)
- Looks up MAC vendor names via external API
- Pulls hostnames from DNS or DHCP (if available)
- Scans for open ports using raw TCP sockets

This is used in Phase 1 (quick scan) and Phase 2 (deep profiling).
"""

import socket
import subprocess
import re
import requests
import logging
import http.client
import json
import time
from pathlib import Path
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Iterable
from scapy.all import ARP, Ether, srp
import netifaces
from ipaddress import IPv4Network

# ──────────────────────────────────────────────────────────────
# Constants and Logging Setup
# ──────────────────────────────────────────────────────────────
THREAD_POOL_SIZE = 400  # number of parallel threads for port scan
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Interface + IP Utilities
# ──────────────────────────────────────────────────────────────

def get_active_interface() -> tuple[str, str, str]:
    """
    Finds the first usable (non-loopback) network interface with an IPv4 address.

    Returns:
        A tuple of (interface_name, local_ip, netmask)
    
    This is used to determine which interface to scan from and what the local subnet is.
    """
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in addrs:
            continue
        for link in addrs[netifaces.AF_INET]:
            ip   = link.get("addr")
            mask = link.get("netmask")
            if ip and mask and not ip.startswith("127."):
                return iface, ip, mask
    raise RuntimeError("No active IPv4 interface found")

def get_local_ip() -> str:
    """
    Shortcut to return just the local IP address.
    Used in some logging/debug contexts where full subnet isn’t needed.
    """
    _, ip, _ = get_active_interface()
    return ip

def get_local_subnet() -> str:
    """
    Uses the active interface's IP and netmask to calculate
    the CIDR subnet string, e.g., '192.168.1.0/24'.

    Used to build the target range for ARP scanning.
    """
    _, ip, mask = get_active_interface()
    network = IPv4Network(f"{ip}/{mask}", strict=False)
    return str(network)

# ──────────────────────────────────────────────────────────────
# Network Discovery (ARP, DNS, DHCP)
# ──────────────────────────────────────────────────────────────

def scan_network(ip_range: str) -> List[dict]:
    """
    Performs an ARP sweep across the given subnet.

    Sends Layer 2 broadcast requests to each IP and waits for responses.
    Returns a list of dicts with 'ip' and 'mac' for each active host.

    This is used for passive device discovery in quick_scan().
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=15, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]

def get_mac_vendor(mac: str) -> str:
    """
    Looks up the vendor name of a MAC address using the macvendors.com API.

    Returns the manufacturer as a string, or "Unknown" if the lookup fails.
    Used to help classify device type.
    """
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=20)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except requests.RequestException:
        logger.warning(f"MAC vendor lookup failed for {mac}")
        return "Unknown"

def reverse_dns(ip: str) -> Optional[str]:
    """
    Attempts to resolve a hostname for a given IP using reverse DNS (PTR).

    Returns:
        Hostname as string, or None if no PTR record exists.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def get_dhcp_hostname(mac: str, leases_file: Path = Path("/var/lib/misc/dnsmasq.leases")) -> Optional[str]:
    """
    Looks for a hostname provided by the client during DHCP request.

    Parses dnsmasq's lease file and extracts the hostname sent by the client
    in option 12. If none is set, returns None.

    Args:
        mac: MAC address to search for
        leases_file: Path to dnsmasq lease file (default used by HomeIDS)
    """
    try:
        with open(leases_file) as fh:
            for line in fh:
                parts = line.split()
                # Format: <expiry> <mac> <ip> <hostname> <client-id>
                if len(parts) >= 4 and parts[1].lower() == mac.lower():
                    hostname = parts[3]
                    return hostname if hostname != "*" else None
    except FileNotFoundError:
        pass
    return None

# ──────────────────────────────────────────────────────────────
# Port Scanning
# ──────────────────────────────────────────────────────────────

def scan_ports(ip: str,
               ports: Optional[Iterable[int]] = None,
               timeout: float = 0.3) -> List[int]:
    """
    TCP port scanner — tries to connect to each port and sees which respond.

    Args:
        ip: Target device IP address
        ports: List of port numbers to check. If None, checks all 1–65535.
        timeout: Timeout in seconds for each connection attempt

    Returns:
        A sorted list of open ports (integers)

    This is used in both quick_scan and profile_device to identify running services.
    It uses raw TCP sockets and a thread pool for parallelism.
    """
    ports = list(ports) if ports is not None else list(range(1, 65536))

    def probe(port: int) -> Optional[int]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((ip, port)) == 0 else None

    with ThreadPoolExecutor(max_workers=min(len(ports), THREAD_POOL_SIZE)) as ex:
        return sorted(p for p in ex.map(probe, ports) if p is not None)
