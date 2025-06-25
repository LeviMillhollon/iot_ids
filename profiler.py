"""
Builds enriched device profiles from raw discovery data:
- Classifies device type
- Combines metadata into structured profiles
- Saves/loads profiles
"""
import json
from typing import List, Optional, Iterable
from discovery import *

# Keyword sets for classification

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
    "windows", "macbook", "ubuntu", "debian", "linux", "pc", "desktop", "laptop", "intel",
    "kali", "raspberry"
}

CONSOLE_KEYWORDS = {
    "xbox", "playstation", "nintendo", "hai"
}

OTHER_KEYWORDS = {
    "rest"
}

# -------------------- Classification Logic -------------------- #

def classify_device(vendor: str,
                    dns_name: str = "",
                    http_banner: str = "",
                    open_ports: Optional[Iterable[int]] = None) -> tuple[str, float, str]:
    """Classifies device type using heuristics and port indicators."""
    open_ports = list(open_ports or [])
    fields = [vendor, dns_name, http_banner]
    lowered = [(f or "").lower() for f in fields]

    def match_score(keywords):
        return sum(1 for k in keywords for f in lowered if k in f)

    scores = {
        "Camera": match_score(CAMERA_VENDORS) + (554 in open_ports),
        "TV": match_score(TV_VENDORS) + (8009 in open_ports),
        "Listening_device": match_score(LISTENING_VENDORS),
        "Cell Phone": match_score(PHONE_VENDORS),
        "printer": match_score(PRINTER_VENDORS) + (9100 in open_ports),
        "router": match_score(ROUTER_KEYWORDS) + (53 in open_ports),
        "Computer": match_score(COMPUTER_KEYWORDS),
        "Game Console": match_score(CONSOLE_KEYWORDS),
        "Other": match_score(OTHER_KEYWORDS)
    }

    max_score = max(scores.values())
    if max_score == 0:
        return "unknown", 0.0, "None"

    for k in scores:
        scores[k] /= max_score

    best = max(scores, key=scores.get)
    confidence = round(scores[best], 2)
    label = "High" if confidence >= 0.85 else "Moderate" if confidence >= 0.5 else "Low"

    return best, confidence, label

# -------------------- Profiling Pipeline -------------------- #

def discover_and_profile() -> List[dict]:
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

        model, firmware = get_device_info(ip)
        

        dev_type, score, label = classify_device(vendor, dns, banner, ports)

        profile = {
            "Device Type": dev_type,
            "DNS": dns or "N/A",
            "IP": ip,
            "vendor": vendor,
            "MAC": mac,
            "HTTP banner": banner or "N/A",
            "Open Ports": ports,
            "Model": model,         
            "Firmware": firmware, 
            "Confidence Label": label,
            "Score": score,
            "Can Spy": dev_type == "TV"
        }
        profiles.append(profile)

        print(f"[+] {ip} → {dev_type} ({label} {score}  Model: {model}, FW: {firmware})")

    return profiles


def save_discovered_devices(devices: List[dict], path: str = 'devices.json') -> None:
    with open(path, 'w') as f:
        json.dump(devices, f, indent=2)


def load_profiles(path: str = 'devices.json') -> List[dict]:
    with open(path, 'r') as f:
        return json.load(f)


def get_device_profiles() -> List[dict]:
    return discover_and_profile()
