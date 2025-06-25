"""
Handles raw network discovery and data collection:
- Determines local network
- Scans for live hosts via ARP
- Fetches MAC vendor, DNS reverse lookup, HTTP banners
- (Placeholder) Port scanni ng
"""
import socket
import subprocess
import re
import requests
import logging
import http.client
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Iterable
from scapy.all import ARP, Ether, srp
#from onvif import ONVIFCamera

# Constants
THREAD_POOL_SIZE = 300
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# Logging Setup
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

# -------------------- Network Utilities -------------------- #

def get_active_ip() -> str:
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
            m = re.search(r"(?:Subnet Mask|netmask)[^\d]+(\d+\.\d+\.\d+\.\d+)", block)
            if m:
                mask = m.group(1)
                cidr = sum(bin(int(o)).count("1") for o in mask.split('.'))
                net_parts = [
                    str(int(local_ip.split('.')[i]) & int(mask.split('.')[i]))
                    for i in range(4)
                ]
                return f"{'.'.join(net_parts)}/{cidr}"
    raise RuntimeError("Could not determine subnet.")

# -------------------- Discovery / Scanning -------------------- #

def scan_network(ip_range: str) -> List[dict]:
    """Sends ARP packets to discover active devices on the subnet."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=10, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]


def get_mac_vendor(mac: str) -> str:
    """Looks up MAC vendor using external API."""
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
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


def get_http_banner(ip: str, timeout: float = 3.0) -> Optional[str]:
    """
    Try HTTP HEAD for a Server header, fall back to GET if none,
    return None on failure.
    """
    url = f"http://{ip}"
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        if server := r.headers.get("Server"):
            return server
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return r.headers.get("Server", "Unknown")
    except requests.RequestException:
        return None


def scan_ports(ip: str,
               ports: Optional[Iterable[int]] = None,
               timeout: float = 0.3) -> List[int]:
    
    open_ports: List[int] = [] 
    '''
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
    
    return sorted(open_ports) '''
    return 0




    


def get_device_info(ip: str, timeout: float = 3.0) -> tuple[str, str]:
    """
    Attempts to discover (model, firmware) via:
      1) HTTP JSON endpoints
      2) HTML home-page scraping
      3) Active SSDP M-SEARCH → parse DeviceDescription.xml
      4) SSH/Telnet banner parsing
    Returns (model, firmware) or ('unknown','unknown').
    """

    # 1) HTTP/REST JSON endpoint (as before)
    for path in ("/status", "/api/v1/device/info", "/info"):
        try:
            resp = requests.get(f"http://{ip}{path}", timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                m = data.get("model") or data.get("deviceModel")
                f = data.get("firmwareVersion") or data.get("version")
                if m or f:
                    return (m or "unknown", f or "unknown")
        except Exception:
            pass

    # 2) HTML home-page scraping
    try:
        resp = requests.get(f"http://{ip}", timeout=timeout)
        if resp.status_code == 200 and resp.text:
            html = resp.text
            # Look for obvious patterns
            m = re.search(r'Model[: ]*<[^>]*>([\w\-\. ]+)</', html, re.IGNORECASE)
            f = re.search(r'Firmware[: ]*([0-9]+\.[0-9]+\.[0-9]+)', html)
            # Fallback to <title>
            if not m:
                title = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
                m = title
            if m or f:
                return (m.group(1).strip() if m else "unknown",
                        f.group(1)           if f else "unknown")
    except Exception:
        pass

    # 3) Active SSDP M-SEARCH for UPnP
    try:
        ssdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ssdp.settimeout(timeout)
        msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST:239.255.255.250:1900',
            'MAN:"ssdp:discover"',
            'MX:1',
            'ST:upnp:rootdevice', '', '']).encode('utf-8')
        ssdp.sendto(msg, ('239.255.255.250', 1900))
        data, _ = ssdp.recvfrom(1024)
        # Find the LOCATION header
        loc = re.search(br'LOCATION:([^\r\n]+)', data, re.IGNORECASE)
        if loc:
            url = loc.group(1).decode().strip()
            # Fetch and parse
            conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
            path = url.split(f"{ip}")[-1]
            conn.request("GET", path)
            res = conn.getresponse()
            xml = res.read()
            tree = ElementTree.fromstring(xml)
            ns = {"upnp":"urn:schemas-upnp-org:device-1-0"}
            model = tree.findtext(".//upnp:modelName", namespaces=ns)
            fw    = tree.findtext(".//upnp:firmwareVersion", namespaces=ns)
            if model or fw:
                return (model or "unknown", fw or "unknown")
    except Exception:
        pass

    # 4) SSH/Telnet banner parsing (as before)
    for port in (22, 23):
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                banner = s.recv(512).decode("utf-8", errors="ignore")
                m_model = re.search(r'(?:Model|DeviceModel)[\s:]*([\w\-\.\_ ]+)', banner)
                m_fw    = re.search(r'[_\sv]?(\d+\.\d+\.\d+)', banner)
                if m_model or m_fw:
                    return (m_model.group(1).strip() if m_model else "unknown",
                            m_fw.group(1)           if m_fw    else "unknown")
        except Exception:
            continue

    return ("unknown", "unknown")    
    

    def get_device_info_onvif(ip: str, user: str='admin', pwd: str='admin') -> tuple[str, str]:
        try:
            cam = ONVIFCamera(ip, 80, user, pwd)
            info = cam.devicemgmt.GetDeviceInformation()
            return (info.Model, info.FirmwareVersion)
        except Exception:
            return ("unknown", "unknown")
