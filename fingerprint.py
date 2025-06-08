import subprocess, re, socket, requests
import json
from scapy.all import ARP, Ether, srp


def get_active_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def get_local_subnet():
    local_ip = get_active_ip()
    output = subprocess.check_output("ipconfig", encoding="utf-8")
    blocks = output.split("\r\n\r\n")
    for block in blocks:
        if local_ip in block:
            ip_line = re.search(r"IPv4 Address[^\d]+(" + re.escape(local_ip) + r")", block)
            mask_line = re.search(r"Subnet Mask[^\d]+(\d+\.\d+\.\d+\.\d+)", block)
            gw_line = re.search(r"Default Gateway[^\d]+(\d+\.\d+\.\d+\.\d+)", block)
            if ip_line and mask_line and gw_line and gw_line.group(1).strip():
                ip = ip_line.group(1)
                mask = mask_line.group(1)
                ip_parts = list(map(int, ip.split(".")))
                mask_parts = list(map(int, mask.split(".")))
                net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
                cidr_bits = sum(bin(x).count("1") for x in mask_parts)
                return f"{'.'.join(net_parts)}/{cidr_bits}"
    raise RuntimeError("Could not determine local subnet.")

def scan_network(ip_range):
    print(f"[+] Scanning network range: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(ether/arp, timeout=10, verbose=False)[0]
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]

def get_mac_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_http_banner(ip):
    try:
        r = requests.get(f"http://{ip}", timeout=10)
        return r.headers.get('Server', 'Unknown')
    except:
        return None

def discover_and_profile():
    # Vendor classifiers
    camera_vendors = [
        "hikvision", "dahua", "reolink", "wyze", "arlo", "nest", "ezviz",
        "ring", "amcrest", "uniview", "logitech", "vtech"
    ]
    tv_vendors = [
        "samsung", "lg", "sony", "vizio", "tcl", "hisense", "panasonic",
        "sharp", "philips", "roku", "tcl"
    ]
    listening_vendors = [
        "google", "amazon", "apple", "sonos", "xiaomi", "baidu", "alexa",
        "homepod", "echo"
    ]

    ip_range = get_local_subnet()
    devices = scan_network(ip_range)

    profiles = []
    for dev in devices:
        vendor = get_mac_vendor(dev["mac"])
        vendor_lc = vendor.lower()
        dns = reverse_dns(dev["ip"])
        banner = get_http_banner(dev["ip"])

        device_type = "unknown"
        if any(k in vendor_lc for k in camera_vendors):
            device_type = "camera"
        elif any(k in vendor_lc for k in tv_vendors):
            device_type = "tv"
        elif any(k in vendor_lc for k in listening_vendors) or "alexa" in (dns or "") or "homepod" in (banner or ""):
            device_type = "listening_device"

        profile = {
            "ip": dev["ip"],
            "mac": dev["mac"],
            "vendor": vendor,
            "dns": dns or "N/A",
            "http_banner": banner or "N/A",
            "device_type": device_type,
            "is_iot": device_type != "unknown"
        }

        profiles.append(profile)

    for p in profiles:
        print(f"\nDevice @ {p['ip']}")
        print(f"  MAC: {p['mac']} | Vendor: {p['vendor']}")
        print(f"  DNS: {p['dns']} | HTTP Banner: {p['http_banner']}")
        print(f"  Type: {p['device_type']} | IoT-like: {'Yes' if p['is_iot'] else 'No'}")

    return profiles

def get_device_profiles():
    return discover_and_profile()



def save_discovered_devices(devices, path='devices.json'):
    with open(path, 'w') as f:
        json.dump(devices, f, indent=2)



if __name__ == "__main__":
    devices = discover_and_profile()
    save_discovered_devices(devices)