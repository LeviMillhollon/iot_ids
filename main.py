#!/usr/bin/env python3
"""
main.py — HomeIDS Orchestrator

Runs all three phases of the IoT IDS system:

1️  Quick LAN scan to inventory home devices  
2️  Deep Nmap scan of anything that connects to the HomeIDS AP  
3️  Live packet sniffing with:
     • Suricata for signatures  
     • behavioral_detect() for anomalies

This is the heart of the system — it kicks everything off and spins up
the watchers and packet processor.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import List, Dict

from scapy.all import sniff, IP  

from classifier import Classifier
#from detection import run_detections
from behavioral_engine import behavioral_detect
from discovery import (
    get_local_subnet,
    scan_network,
    get_mac_vendor,
    reverse_dns,
    scan_ports,
    get_dhcp_hostname,
)
from logger import log_alert
from nmap_runner import profile_device
from pathlib import Path






# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
AP_IFACE      = "wlan1"                                # monitor interface
SURICATA_CFG  = "/etc/suricata/suricata.yaml"
SURICATA_EVE  = "/var/log/suricata/eve.json"

BASIC_FILE    = "devices_home.json"   # quick-scan results
AP_FILE       = "devices_ap.json"     # deep-scan results
LEASES_FILE   = "/var/lib/misc/dnsmasq.leases"
PENDING_FILE = Path("pending_devices.json")
POLL_INTERVAL = 10                     # seconds between AP polls

# ──────────────────────────────────────────────────────────────────────────────
# Globals & locks
# ──────────────────────────────────────────────────────────────────────────────
lock: threading.Lock = threading.Lock()
home_profiles: Dict[str, dict] = {}
ap_profiles:   Dict[str, dict] = {}

eve_offset = 0  # incremental read pointer into eve.json

# ──────────────────────────────────────────────────────────────────────────────
# Helper: wait for interface to be up
# ──────────────────────────────────────────────────────────────────────────────
def wait_for_iface(iface: str, timeout: int = 40):
    """
    Blocks until the given network interface is active.

    Specifically, this checks /sys/class/net/<iface>/operstate once per second.
    If it reads "up", it continues. If it doesn’t come up in <timeout> seconds,
    it throws a TimeoutError and bail.

    This is used to ensure wlan1 is fully initialized before packet capture begins.
    """
    oper_state = f"/sys/class/net/{iface}/operstate"
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(oper_state) as fh:
                if fh.read().strip() == "up":
                    print(f"[+] Interface {iface} is up.")
                    return
        except FileNotFoundError:
            pass
        time.sleep(1)
    raise TimeoutError(f"{iface} not present or not up after {timeout}s")

# ──────────────────────────────────────────────────────────────────────────────
# Phase 1 · Quick passive scan of home LAN
# ──────────────────────────────────────────────────────────────────────────────
def quick_scan():
    """
    Runs an initial one-time scan of the home LAN (Phase 1).

    - Uses ARP to find devices on the local subnet
    - Looks up each MAC address vendor
    - Attempts reverse DNS resolution
    - Scans for open ports on each host
    - Classifies device type based on vendor, hostname, and ports
    - Saves result as a list of structured profiles → devices_home.json

    This gives a passive snapshot of the current network without requiring user action.
    """
    print("[+] Running quick network discovery (home network)…")
    subnet = get_local_subnet()
    for dev in scan_network(subnet):
        ip, mac = dev["ip"], dev["mac"].lower()
        if mac in home_profiles:
            continue
        vendor = get_mac_vendor(mac)
        dns    = reverse_dns(ip) or "N/A"
        ports  = scan_ports(ip)
        result = Classifier.classify_device(vendor, dns, ports)
        home_profiles[mac] = {
            "device_type": result.device_type.value,
            "vendor": vendor, "dns": dns,  "ip": ip, 
            "open_ports": ports,"score": result.confidence, 
            "label": result.label, "mac": mac,
        }
    with open(BASIC_FILE, "w") as fh:
        json.dump(list(home_profiles.values()), fh, indent=2)
    print(f"✅ Quick scan saved {len(home_profiles)} devices → {BASIC_FILE}")

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2 · Deep scan of AP-connected clients
# ──────────────────────────────────────────────────────────────────────────────
def _get_connected_macs(iface: str = AP_IFACE) -> set[str]:
    """
    Uses `iw dev <iface> station dump` to list all MACs currently connected
    to the access point. These are clients we're responsible for monitoring.

    Returns a set of lowercase MAC addresses.
    """
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "station", "dump"], text=True
        )
        return {m.lower() for m in re.findall(r"Station\s+([0-9a-f:]{17})", out, re.I)}
    except subprocess.CalledProcessError:
        return set()

def _lookup_ap_ip(mac: str) -> str | None:
    """
    Searches the dnsmasq DHCP leases file for the IP address assigned
    to the given MAC address. If found, returns it as a string.
    Returns None if the MAC is missing or the file doesn’t exist.

    Used to pair MACs from the AP interface with actual IPs for scanning.
    """
    try:
        with open(LEASES_FILE) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1].lower() == mac:
                    return parts[2]
    except FileNotFoundError:
        pass
    return None

def deep_scan_watcher() -> None:
    """
    Background thread that runs every POLL_INTERVAL seconds.

    - Checks which MACs are connected to the access point (wlan1)
    - For any MAC not already profiled:
        - Finds its IP from dnsmasq leases
        - Tries to get vendor, hostname, and classify device type
        - Adds it to a pending list
    - Writes the pending list to disk (dashboard uses this)
    - Iterates over pending list:
        - Runs Nmap profile scan
        - Saves deep scan result into devices_ap.json
        - Removes that MAC from the pending list

    This is Phase 2 of the system — actively profiling devices
    that connect to the HomeIDS AP.
    """
    print("[+] Starting deep scan watcher…")
    while True:
        connected_macs = _get_connected_macs()
        with lock:
            scanned_macs = set(ap_profiles.keys())
        
        # Identify pending devices
        pending_devices = []
        for mac in connected_macs - scanned_macs:
            ip = _lookup_ap_ip(mac)
            if ip:
                vendor = get_mac_vendor(mac)
                # Get DNS name if available
                dns = get_dhcp_hostname(mac) or reverse_dns(ip) or "Unknown"
                # Classify device type using vendor and DNS name
                classification = Classifier.classify_device(vendor, dns)
                dev_type = classification.device_type.value.lower()
                pending_devices.append({"mac": mac, "ip": ip, "vendor": vendor, "device_type": dev_type})
        
        # Write pending list to file
        with open(PENDING_FILE, "w") as f:
            json.dump(pending_devices, f, indent=2)
        print(f"[+] Updated pending devices: {len(pending_devices)} in {PENDING_FILE}")
        
        # Process each pending device
        for dev in pending_devices[:]:  # Use a copy to modify list during iteration
            mac = dev["mac"]
            ip = dev["ip"]
            dev_type = dev["device_type"]
            print(f"[+] Deep-scanning {mac} @ {ip} as {dev_type}")
            profile = profile_device(ip, mac, dev_type)
            with lock:
                ap_profiles[mac] = profile
            
            # Update devices_ap.json
            with open(AP_FILE, "w") as f:
                json.dump(list(ap_profiles.values()), f, indent=2)
            print(f"✅ Saved deep profile for {mac} → {AP_FILE}")
            
            # Update pending list by removing the scanned device
            pending_devices = [d for d in pending_devices if d["mac"] != mac]
            with open(PENDING_FILE, "w") as f:
                json.dump(pending_devices, f, indent=2)
        
        time.sleep(POLL_INTERVAL)

# ──────────────────────────────────────────────────────────────────────────────
# Suricata integration
# ──────────────────────────────────────────────────────────────────────────────
def ensure_suricata():
    """
    Checks if Suricata is already running. If not, launches it as a daemon.

    Suricata is used to handle all signature-based detection. It watches
    the same interface as the behavioral engine (wlan1), and logs alerts
    to eve.json in JSONL format.
    """
    if subprocess.call(["pidof", "suricata"], stdout=subprocess.DEVNULL) == 0:
        return
    print("[+] Launching Suricata…")
    subprocess.Popen([
        "sudo", "suricata",
        "-i", AP_IFACE,
        "--af-packet",
        "-c", SURICATA_CFG,
        "-D",
    ])
    time.sleep(2)  # give it a moment

def read_suricata_alerts(eve_path: str = SURICATA_EVE) -> List[dict]:
    """
    Reads new entries from Suricata’s eve.json file since last call.

    Uses a global file offset to track our position between reads.
    Parses each new line, filters for event_type=alert, and reformats
    each alert into a simplified dict with useful metadata.

    Returns a list of new alerts ready to be passed to log_alert().
    """
    global eve_offset
    alerts: List[dict] = []
    try:
        with open(eve_path, "r") as fh:
            size = fh.seek(0, os.SEEK_END)
            if size < eve_offset:
                eve_offset = 0  # log rotated
            fh.seek(eve_offset)
            for line in fh:
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("event_type") == "alert":
                    al = evt["alert"]
                    alerts.append({
                        "type": "Suricata Alert",
                        "rule": al.get("signature"),
                        "metadata": al.get("metadata", {}),
                        "community_id": evt.get("community_id"),
                        "dest_geoip":   evt.get("dest_geoip"),
                        "src_geoip":    evt.get("src_geoip"),
                        "category": al.get("category", ""),
                        "severity": al.get("severity"),
                        "src_ip": evt.get("src_ip"),
                        "dst_ip": evt.get("dest_ip"),
                        "src_port": evt.get("src_port"),
                        "dst_port": evt.get("dst_port"),
                        "timestamp": evt.get("timestamp"),
                        "source": "Suricata",
                    })
            eve_offset = fh.tell()
    except FileNotFoundError:
        pass
    return alerts

def suricata_watcher():
    """
    Background thread that reads Suricata alerts once per second.

    - Calls read_suricata_alerts() to pull any new entries from eve.json
    - Forwards each alert to log_alert() so it gets logged like our own

    This continuously feeds signature-based alerts into the main system,
    just like the behavioral engine does.
    """
    while True:
        for alert in read_suricata_alerts():
            log_alert(alert)
        time.sleep(1)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 · Live packet signature / behaviour detections
# ──────────────────────────────────────────────────────────────────────────────
def packet_callback(pkt):
    """
    Called by Scapy every time a packet is captured on wlan1.

    - Checks that it has an IP layer
    - Sends the packet to behavioral_detect()
    - For any alert returned, logs it via log_alert()

    This is Phase 3 of the IDS — behavioral detection engine in action.
    """
    if IP not in pkt:
        return
    for alert in behavioral_detect(pkt):
        log_alert(alert)

# ──────────────────────────────────────────────────────────────────────────────
# Main entry
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        wait_for_iface(AP_IFACE, timeout=40)
    except TimeoutError as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)

    quick_scan()
    ensure_suricata()

    threading.Thread(target=deep_scan_watcher, daemon=True).start()
    threading.Thread(target=suricata_watcher, daemon=True).start()

    print("[+] IDS live — capturing on", AP_IFACE)
    sniff(iface=AP_IFACE, filter="ip", prn=packet_callback, store=False)