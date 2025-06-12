import socket
import subprocess
import requests
import re
import json
from scapy.all import ARP, Ether, srp

import logging
import threading


from concurrent.futures import ThreadPoolExecutor

from typing import List, Optional, Iterable

# bump this up so you can scan more ports simultaneously
THREAD_POOL_SIZE = 200
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


# -------------------- Logging Setup -------------------- #

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

# -------------------- Network Utilities -------------------- #

def get_active_ip():
    """Gets the host's current outbound-facing IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def get_local_subnet() -> str:
    """Determine local subnet in CIDR via ipconfig (Windows) or ifconfig (Unix)."""
    local_ip = get_active_ip()
    try:
        output = subprocess.check_output("ipconfig", encoding="utf-8")
        blocks = output.split("\r\n\r\n")
    except subprocess.CalledProcessError:
        output = subprocess.check_output("ifconfig", encoding="utf-8")
        blocks = output.split("\n\n")

    for block in blocks:
        if local_ip in block:
            # find mask
            m = re.search(r"(?:Subnet Mask|netmask)[^\d]+(\d+\.\d+\.\d+\.\d+)", block)
            if m:
                mask = m.group(1)
                cidr = sum(bin(int(o)).count("1") for o in mask.split('.'))
                net_parts = [str(int(local_ip.split('.')[i]) & int(mask.split('.')[i])) for i in range(4)]
                return f"{'.'.join(net_parts)}/{cidr}"
    raise RuntimeError("Could not determine subnet.")


# -------------------- Scanning & Enrichment -------------------- #

def scan_network(ip_range):
    """Sends ARP packets to discover active devices on the subnet."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=5, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]


def get_mac_vendor(mac):
    """Looks up MAC vendor using external API."""
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except requests.RequestException:
        return "Unknown"


def reverse_dns(ip):
    """Attempts reverse DNS lookup for a given IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_http_banner(ip: str, timeout: float = 3.0) -> str | None:
    """
    Try HTTP HEAD for a Server header, fall back to GET if none,
    return None on failure.
    """
    url = f"http://{ip}"
    try:
        # 1) HEAD is lighter
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        if server := r.headers.get("Server"):
            return server

        # 2) fallback to GET (in case HEAD isn't supported)
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return r.headers.get("Server", "Unknown")
    except requests.RequestException:
        return None

def scan_ports(ip: str,
               ports: Optional[Iterable[int]] = None,
               timeout: float = 0.3) -> List[int]:
    
    open_ports: List[int] = []

    def probe(port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)

    # If no specific ports provided, scan the full range
    target_ports = ports if ports is not None else range(1, 65536)

    # Dispatch probes in a thread pool
    with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
        executor.map(probe, target_ports)
    
    return sorted(open_ports) 


# -------------------- Device Classification -------------------- #

def classify_device(vendor, dns_name="", http_banner="", open_ports=None):
    """Classifies device type using heuristics and port indicators."""
    open_ports = open_ports or []
    fields = [vendor, dns_name, http_banner,]
    lowered = [(f or "").lower() for f in fields]

    def match_score(keywords):
        return sum(1 for k in keywords for f in lowered if k in f)

    scores = {
        "Camera": match_score(CAMERA_VENDORS) + (554 in open_ports),
        "TV": match_score(TV_VENDORS) + (8009 in open_ports),
        "Listening_device": match_score(LISTENING_VENDORS),
        "Cell Phone": match_score(PHONE_VENDORS),
        "printer": match_score(PRINTER_VENDORS) + (9100 in open_ports),
        "router": match_score(ROUTER_KEYWORDS),
        "Computer": match_score(COMPUTER_KEYWORDS),
        "Game Console": match_score(CONSOLE_KEYWORDS)
    }

    max_score = max(scores.values())
    if max_score == 0:
        return "unknown", 0.0, "None"

    for k in scores:
        scores[k] = scores[k] / max_score

    best = max(scores, key=scores.get)
    confidence = round(scores[best], 2)
    label = "High" if confidence >= 0.85 else "Moderate" if confidence >= 0.5 else "Low"

    return best, confidence, label


# -------------------- Discovery & Profiling -------------------- #

def discover_and_profile():
    """Scans network and builds enriched profiles of discovered devices."""
    subnet = get_local_subnet()
    devices = scan_network(subnet)
    profiles = []

    for dev in devices:
        ip, mac = dev["ip"], dev["mac"]
        vendor = get_mac_vendor(mac)
        dns = reverse_dns(ip)
        banner = get_http_banner(ip)
        ports = scan_ports(ip)

        dev_type, score, label = classify_device(vendor, dns, banner, ports)

        profile = {
            "ip": ip, "mac": mac, "vendor": vendor,
            "dns": dns or "N/A", "http_banner": banner or "N/A",
            "open_ports": ports, 
            "device_type": dev_type, "confidence_score": score,
            "confidence_label": label, "is_iot": dev_type != "unknown"
        }
        profiles.append(profile)

        print(f"\n[+] Device @ {ip}")
        print(f"    MAC/Vendor : {mac} / {vendor}")
        print(f"    DNS        : {profile['dns']} | HTTP: {profile['http_banner']}")
        print(f"    Open Ports : {ports or 'None'}")
        print(f"    → {dev_type} (Confidence: {label} {score})")

    return profiles

def get_device_profiles():
    return discover_and_profile()


def save_discovered_devices(devices, path='devices.json'):
    with open(path, 'w') as f:
        json.dump(devices, f, indent=2)


def load_profiles(path="devices.json"):
    """Loads device profiles from a saved JSON file."""
    with open(path, "r") as f:
        return json.load(f)        


# -------------------- Keyword Sets -------------------- #

CAMERA_VENDORS = {
    "hikvision", "dahua", "reolink", "wyze", "arlo", "nest", "ezviz",
    "ring", "amcrest", "uniview", "logitech", "vtech"
}

TV_VENDORS = {
    "samsung", "lg", "sony", "vizio", "tcl", "hisense", "panasonic",
    "sharp", "philips", "roku"
}

LISTENING_VENDORS = {
    "google", "amazon", "apple", "sonos", "xiaomi", "baidu", "alexa",
    "homepod", "echo"
}

PHONE_VENDORS = {
    "apple", "iphone", "samsung", "huawei", "xiaomi", "oneplus", "pixel",
    "motorola", "nokia", "oppo", "vivo", "s20"
}

PRINTER_VENDORS = {
    "hp", "brother", "epson", "canon", "ricoh", "kyocera", "xerox", "lexmark"
}

ROUTER_KEYWORDS = {
    "router", "access point", "gateway", "fios", "xfinity", "netgear", "asus",
    "tplink", "tp-link", "dlink", "d-link", "linksys", "arris", "orbi"
}

COMPUTER_KEYWORDS = {
    "windows", "macbook", "ubuntu", "debian", "linux", "pc", "desktop", "laptop", "intel"
}

CONSOLE_KEYWORDS = {
    "xbox", "playstation", "nintendo"
}



# -------------------- Main Entry Point -------------------- #

if __name__ == "__main__":
    devices = discover_and_profile()
    save_discovered_devices(devices)
  
    
