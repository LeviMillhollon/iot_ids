"""
Handles raw network discovery and data collection:
- Determines local network
- Scans for live hosts via ARP
- Fetches MAC vendor, DNS reverse lookup, HTTP banners
- Port scanning
"""
import socket
import subprocess
import re
import requests
import logging
import http.client
import socket, json, time
from pathlib import Path
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Iterable
from scapy.all import ARP, Ether, srp
import netifaces
from ipaddress import IPv4Network


# Constants
THREAD_POOL_SIZE = 400
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# Logging Setup
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

# -------------------- Network Utilities -------------------- #



def get_active_interface() -> tuple[str, str, str]:
    """
    Finds the first non‑loopback interface with an IPv4 address.
    Returns (iface_name, ip_address, netmask).
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
    """Returns the local IP of the first active interface."""
    _, ip, _ = get_active_interface()
    return ip

def get_local_subnet() -> str:
    """
    Returns the local subnet in CIDR notation, e.g. '192.168.1.0/24'.
    """
    _, ip, mask = get_active_interface()
    network = IPv4Network(f"{ip}/{mask}", strict=False)
    return str(network)

# -------------------- Discovery / Scanning -------------------- #

def scan_network(ip_range: str) -> List[dict]:
    """Sends ARP packets to discover active devices on the subnet."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=15, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]


def get_mac_vendor(mac: str) -> str:
    """Looks up MAC vendor using external API."""
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=20)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except requests.RequestException:
        logger.warning(f"MAC vendor lookup failed for {mac}")
        return "Unknown"


def reverse_dns(ip: str) -> Optional[str]:
    """Attempts reverse DNS lookup for a given IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    
def get_dhcp_hostname(mac: str, leases_file: Path = Path("/var/lib/misc/dnsmasq.leases")) -> Optional[str]:
    """
    Read dnsmasq.leases and return the hostname a client
    sent in its DHCP option 12, if present.
    """
    try:
        with open(leases_file) as fh:
            for line in fh:
                parts = line.split()
                # dnsmasq format: <expiry> <mac> <ip> <hostname> <client-id>
                if len(parts) >= 4 and parts[1].lower() == mac.lower():
                    hostname = parts[3]
                    return hostname if hostname != "*" else None
    except FileNotFoundError:
        pass
    return None    



def scan_ports(ip: str,
               ports: Optional[Iterable[int]] = None,
               timeout: float = 0.3) -> List[int]:
    
    ports = list(ports) if ports is not None else list(range(1, 65536))

    def probe(port: int) -> Optional[int]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((ip, port)) == 0 else None

    with ThreadPoolExecutor(max_workers=min(len(ports), THREAD_POOL_SIZE)) as ex:
        return sorted(p for p in ex.map(probe, ports) if p is not None)

    #return 0




    


