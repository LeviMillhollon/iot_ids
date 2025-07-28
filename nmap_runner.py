#!/usr/bin/env python3
"""
nmap_runner.py
==============

This module deep-scans a single device using Nmap and builds out a full profile
for dashboard/reporting purposes.

How it works:
- First, do basic TCP scan to find open ports
- Then launch Nmap with a targeted list of scripts and flags
- Finally, parse the XML output to extract service banners, firmware, CVEs, etc.

This powers the Phase 2 deep scan in the IDS system.
"""

from __future__ import annotations
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Optional

from discovery import get_mac_vendor, reverse_dns, get_dhcp_hostname, scan_ports
from classifier import Classifier

# ───────────────────────── Script bundles ─────────────────────────
# Base scripts used for all devices (grab banners, HTTP info, vuln checks)
BASE_SCRIPTS: List[str] = [
    #"vulners",                   # map versions → CVEs
    "vuln",                     # generic vulnerability summary (uncomment if desired)
    "banner",                    # basic banner grab
    "http-enum",
    "http-title",                # grab HTML title for any web interface
    "http-server-header",
    "http-robots.txt",           # Check for web server robots file (common in IoT)
    "http-favicon",              # Fingerprint via favicon (useful for IoT web UIs)
    "ssl-cert",                  # grab cert metadata from HTTPS
    "http-default-accounts",     # check for known default HTTP creds
    "http-auth-finder",          # probe different auth schemes
    "ftp-anon",                  # anonymous FTP upload/download
    "broadcast-dns-service-discovery",
    "dns-service-discovery",
    "upnp-info",                 # UPnP for plug-and-play devices
    #"ip-geolocation-geoplugin",
    "mqtt-subscribe"             # subscribe to public MQTT topics
]
# Extra scripts for specific device types (e.g. cameras get RTSP, computers get SMB)
DEVICE_SCRIPT_BUNDLES: Dict[str, List[str]] = {
    "camera": [
        "rtsp-methods",          # RTSP for camera streaming
        "rtsp-url-brute",        # Brute-force RTSP paths
        "http-methods",          # Web interface verb enumeration
        "broadcast-upnp-info",   # UPnP discovery
        "broadcast-wsdd-discover", # WSD discovery
        "ssl-heartbleed",        # HTTPS vulnerability check
    ],
    "tv": [
        "broadcast-upnp-info",   # UPnP for media devices
        "broadcast-wsdd-discover", # WSD discovery
        "http-methods",          # Web interface verb enumeration
    ],
    "sound": [
        "broadcast-upnp-info",   # UPnP for media devices
        "broadcast-wsdd-discover", # WSD discovery
        "http-methods",          # Web interface verb enumeration
    ],
    "computer": [
        "smb-os-discovery",      # SMB for OS fingerprinting
        "smb-enum-shares",       # SMB share enumeration
        "rdp-ntlm-info",         # RDP NTLM info
        "ssh-hostkey",           # SSH fingerprinting
        "nbstat",                # NetBIOS info
    ],
}

# Regex for CVE strings
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

def _script_set_for(dev_type: str) -> List[str]:
    """
    Returns the full list of scripts to run for a given device type.
    Combines base scripts with any category-specific ones.
    """
    return BASE_SCRIPTS + DEVICE_SCRIPT_BUNDLES.get(dev_type.lower(), [])

# ───────────────────────── Nmap runner ───────────────────────────

def run_nmap(ip: str, scripts: List[str], open_ports: List[int]) -> Optional[str]:
    """
    Actually runs Nmap against the target IP using only discovered ports.

    - Performs SYN scan, version detection, OS fingerprinting, and NSE script runs
    - Returns the raw XML output from Nmap as a string
    - If Nmap fails, it logs the error and returns None
    """
    if not open_ports:
        return None

    # Build the -p argument from discovered port numbers
    port_arg = ",".join(str(p) for p in open_ports)
    script_arg = ",".join(sorted(set(scripts)))

    cmd = [
        "nmap",
        "-sS",               # TCP SYN scan
        "-p", port_arg,      # only the discovered ports
        "-sV",               # service/version detection
        "-O",                # OS detection
        "-T4",               # faster execution
        "-Pn",               # skip host discovery
        "--max-retries", "2",
        "--script", script_arg,
        "-oX", "-",        # XML to stdout
        ip,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        print(f"[stderr]\n{res.stderr}")   # ← test
        if res.returncode != 0:
            print(f"[!] Nmap exited {res.returncode} for {ip}")
        return res.stdout
    except Exception as exc:
        print(f"[!] Nmap error for {ip}: {exc}")
        return None

# ───────────────────────── XML parser ────────────────────────────
def parse_xml(xml_string: str) -> Tuple[
        List[int], List[str],
        Optional[str], Optional[str],
        List[str], Optional[str]
]:
    """
    Parses Nmap XML output and pulls out:

    - List of open ports
    - Service banners (name/version/product)
    - Model & firmware guesses
    - CVEs from vuln scripts
    - OS fingerprint name

    Everything gets deduplicated and sorted before being returned.
    """
    open_ports: List[int] = []
    services:   List[str] = []
    vulns:      List[str] = []
    model:      Optional[str] = None
    firmware:   Optional[str] = None
    os_name:    Optional[str] = None

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as err:
        print(f"[!] XML parsing failed: {err}")
        return [], [], None, None, [], None

    # Look for host-level vulnerability scripts
    for scr in root.findall("host/hostscript/script"):
        out = scr.get("output", "") or ""
        for ln in out.splitlines():
            if CVE_RE.search(ln):
                vulns.append(ln.strip())

    # OS fingerprint
    if os_match := root.find("host/os/osmatch"):
        if not model:
            model = os_match.get("name")

    # Go through each open port and scrape metadata
    for port in root.findall(".//port"):
        if (st := port.find("state")) is None or st.get("state") != "open":
            continue
        pid = int(port.get("portid", 0))
        open_ports.append(pid)

         # Grab service banners and try to guess model/firmware
        if svc := port.find("service"):
            parts = [svc.get(k, "") for k in ("name","product","version","extrainfo")]
            banner = " ".join(filter(None, parts))
            if banner:
                services.append(banner)
            if not model and svc.get("product") and any(
                kw in svc.get("product","" ).lower() for kw in ("camera","router","switch","nas")
            ):
                model = svc.get("product")
            if not firmware and svc.get("version"):
                firmware = svc.get("version")

        # Scan output from port-level NSE scripts
        for scr in port.findall("script"):
            sid = scr.get("id", "")
            out = scr.get("output", "") or ""
            if sid == "vulners":
                import json
                for ln in out.splitlines():
                    try:
                        j = json.loads(ln)
                        if cve := j.get("id"):
                            vulns.append(cve)
                    except json.JSONDecodeError:
                        continue
            else:
                for ln in out.splitlines():
                    if CVE_RE.search(ln):
                        vulns.append(ln.strip())
                if first := out.splitlines()[0] if out.splitlines() else "":
                    services.append(f"{sid}: {first}")

    # dedupe & sort
    return (
        sorted(set(open_ports)),
        sorted(set(services)),
        model,
        firmware,
        sorted(set(vulns)),
        os_name,
    )

# ───────────────────────── Public API ───────────────────────────
def profile_device(ip: str, mac: str, dev_type: str) -> Dict:
    """
    Deep-scans a single device and returns a full profile.

    - Uses custom port scan to get open ports
    - Classifies the device using vendor, hostname, and ports
    - Runs Nmap with a script bundle tailored to device type
    - Parses XML output to extract metadata and vulnerabilities
    - Returns a dict ready to be dropped into devices_ap.json

    If Nmap fails, it still returns a minimal stub profile.
    """

    # 1) Gather vendor + hostname
    vendor = get_mac_vendor(mac) or "Unknown"
    dns    = get_dhcp_hostname(mac) or reverse_dns(ip) or "Unknown"

    # 2) Discover open ports using the custom scanner
    ports = scan_ports(ip)
    
    # 3) Final classification based on real port data
    result = Classifier.classify_device(vendor, dns, ports)

    # 4) Deep scan only those ports with the correct NSE scripts
    scripts = _script_set_for(result.device_type.value)
    xml_output     = run_nmap(ip, scripts, ports)
    if not xml_output:
        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "dns": dns,
            "device_type": result.device_type.value,
            "open_ports": [],
            "services": [],
            "vulns": [],
            "model": "Unknown",
            "firmware": "Unknown",
            #"os": "Unknown",
            "score": result.confidence,
            "label": result.label,
        }

    open_ports, services, model, firmware, vulns, os_name = parse_xml(xml_output)

    return {
        "ip":           ip,
        "mac":          mac,
        "vendor":       vendor,
        "dns":          dns,
        "device_type":  result.device_type.value,
        "open_ports":   open_ports,
        "services":     services,
        "model":        model or "Unknown",
        "firmware":     firmware or "Unknown",
        #"os":           os_name or "Unknown",
        "vulns":        vulns,
        "score":        result.confidence,
        "label":        result.label,
    }

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) != 4:
        sys.exit("Usage: nmap_runner.py <ip> <mac> <type>")
    print(json.dumps(
        profile_device(sys.argv[1], sys.argv[2].lower(), sys.argv[3]),
        indent=2
    ))