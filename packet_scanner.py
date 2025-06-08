# scanner.py

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from datetime import datetime
from fingerprint import *
from detection import run_ids         # ← import your IDS engine
from logger import log_alert
from scapy.all import rdpcap

def load_profiles():
    """
    Call fingerprint.get_device_profiles() and build a lookup dict:
      { "192.168.1.12": { ...profile dict... }, ... }
    """
    profiles_list = get_device_profiles()
    return { p["ip"]: p for p in profiles_list }

def packet_callback(pkt):
    """
    For every sniffed packet:
      1. Lookup device profile
      2. Run IDS detection rules
      3. Print the packet summary
    """
    if IP not in pkt:
        return  # skip non-IP packets

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto  = pkt[IP].proto
    timestamp = datetime.now().strftime("%H:%M:%S")

    # 1. Lookup the source device profile (if it exists)
    src_profile = device_profiles.get(src_ip)

    # 2. Run your IDS engine (this will call log_alert() on matches)
    run_ids({ "src_ip": src_ip }, src_profile)

    # 3. Continue with your existing print/debug logic:
    if src_profile:
        src_vendor = src_profile["vendor"]
        src_type   = src_profile["device_type"]
        iot_flag   = "IoT" if src_profile["is_iot"] else "Non-IoT"
    else:
        src_vendor = "Unknown"
        src_type   = "unknown"
        iot_flag   = "Non-IoT"

    print(f"\n[{timestamp}] {iot_flag} Packet: {src_ip} ({src_vendor}/{src_type}) → {dst_ip} | Protocol: {proto}")

    # TCP details
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        print(f"  TCP {sport} → {dport} | Flags: {flags}")

        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
                if any(keyword in payload for keyword in ["HTTP", "GET", "Host:"]):
                    print(f"    ▶ HTTP: {payload.splitlines()[0]}")
            except Exception:
                pass

    # UDP details
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        print(f"  UDP {sport} → {dport}")

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="ignore")
            print(f"    ▶ DNS Query: {qname}")

if __name__ == "__main__":
    # 1. Load device profiles into a global dict
    print("[+] Running fingerprint engine and building profile lookup...\n")
    device_profiles = load_profiles()

    profiled_devices = discover_and_profile()
    save_discovered_devices(profiled_devices)
    print(f"✅ Saved {len(profiled_devices)} devices to devices.json")

    device_profiles = { p["ip"]: p for p in profiled_devices }

    # 2. Start live packet sniffing
    print("\n[+] Starting live packet capture. Press Ctrl+C to stop.")
    sniff(filter="ip", prn=packet_callback, store=False)

    

            # Read packets from a PCAP file
    '''packets = rdpcap("test_traffic.pcap")

    # Feed each packet into your existing callback
    for pkt in packets:
        packet_callback(pkt)'''
