#!/usr/bin/env python3
"""
IoT IDS orchestrator

Phase 1  • Quick scan of the home LAN and JSON export
Phase 2  • Deep scan of devices that associate with the IDS access-point
Phase 3  • Passive packet sniffing + Suricata alert ingestion
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

from scapy.all import sniff, IP  # type: ignore

from classifier import Classifier
from detection import run_detections
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
    """Block until *iface* reports oper-state "up"."""
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
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "station", "dump"], text=True
        )
        return {m.lower() for m in re.findall(r"Station\s+([0-9a-f:]{17})", out, re.I)}
    except subprocess.CalledProcessError:
        return set()

def _lookup_ap_ip(mac: str) -> str | None:
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
    Continuously watch for new stations on the AP, classify their type using
    vendor and available data, deep-scan each, and write profiles to devices_ap.json.
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
    """Start Suricata (daemon) on AP_IFACE if not already running."""
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
    """Return only new Suricata alerts since last call."""
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
    while True:
        for alert in read_suricata_alerts():
            log_alert(alert)
        time.sleep(1)

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 · Live packet signature / behaviour detections
# ──────────────────────────────────────────────────────────────────────────────
def packet_callback(pkt):
    if IP not in pkt:
        return
    for alert in run_detections(pkt):
        #alert.update(src_ip=pkt[IP].src, timestamp=datetime.utcnow().isoformat())
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