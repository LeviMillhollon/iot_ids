
"""
behavioral_engine.py

This module implements the behavioral detection engine for HomeIDS.
It analyzes live network traffic captured via Scapy and applies heuristic rules 
to identify suspicious or malicious activity. These include port scanning, 
brute-force login attempts, DDoS patterns, command-and-control (C2) beaconing, 
and data exfiltration behaviors.

The engine maintains time-based tracking structures for each type of attack and 
evaluates each packet in real-time to detect violations of expected behavior thresholds.
Alerts are constructed, severity-tagged, and logged for dashboard visualization.

"""
from __future__ import annotations

import time
import threading
import statistics
import re
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Tuple

from scapy.all import IP, TCP, UDP, Raw  
from scapy.layers.dns import DNSQR       

from logger import log_alert

# ──────────────────────────────────────────────────────────────────────────────
# Config thresholds
# ──────────────────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD     = 16    # unique dest ports
PORT_SCAN_WINDOW        = 1    # seconds

BRUTE_FORCE_THRESHOLD   = 150     # failures or rapid attempts (lowered for faster detection)
BRUTE_FORCE_WINDOW      = 1    # seconds (shorter for faster attacks)
BRUTE_PORTS             = {22, 23, 80, 443}
BRUTE_CONNECTION_THRESHOLD = 150 # rapid TCP connections
BRUTE_CONNECTION_WINDOW = 1    # seconds

DDOS_RATE_THRESHOLD     = 65   # packets per source-destination pair
DDOS_TIME_WINDOW        = .5    # seconds
DDOS_TOTAL_PACKETS_THRESHOLD = 275  # total packets to destination
DDOS_UNIQUE_SOURCES_THRESHOLD = 20   # unique sources to destination

CNC_TOTAL_THRESHOLD     = 10    # total hits
CNC_MIN_PER_HOST        = 7     # per distinct host
CNC_HOSTS_MAX           = 4     # distinct dst hosts
CNC_TIME_WINDOW         = 60    # seconds
CNC_PERIODIC_CV_MAX     = 0.7   # coefficient of variation

EXFIL_VOLUME_THRESHOLD  = 10_000_000  # 10MB for streaming/gaming
EXFIL_STRICT_THRESHOLD  = 1_000_000   # 1MB for non-whitelisted traffic
EXFIL_WINDOW_SECONDS    = 10

STREAMING_PORTS         = {554, 8554, 3074, 3478}  # RTSP, gaming - Needs more work.
KNOWN_STREAMING_DEVICES = {"10.10.0.1"}  # Camera
KNOWN_STREAMING_DOMAINS = {"netflix.com", "youtube.com", "googlevideo.com", "xboxlive.com"}

# Dedup cooldowns
COOLDOWN_SEC = 0  # fallback for behavioral detections

# ──────────────────────────────────────────────────────────────────────────────
# Severity & colour mapping
# ──────────────────────────────────────────────────────────────────────────────
SEV_LABEL_TO_NUM = {
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
    "critical": 1,  # map critical to high
    "unknown":  4,
}
SEV_LABEL_TO_COLOR = {
    "high":     "background-color:red",
    "medium":   "background-color:orange",
    "low":      "background-color:lightgreen",
    "info":     "background-color:lightgray",
    "critical": "background-color:darkred",
    "unknown":  "background-color:lightgray",
}


# ──────────────────────────────────────────────────────────────────────────────
# Thread-safe state for each detection category
# These structures keep track of activity (by IP) so it can detect patterns
# like port scanning, brute-forcing, DDoS floods, C2 beacons, and exfiltration.
# Each one stores recent activity in memory and is pruned as new packets arrive.
# They're wrapped with threading.Lock to avoid race conditions since packets
# are processed in a multithreaded environment.
# ──────────────────────────────────────────────────────────────────────────────

_lock = threading.Lock()  # Makes sure multiple threads don’t mess with state at the same time

# Tracks which ports each source IP is trying to hit (for detecting port scans)
_scan_tracker = defaultdict(lambda: deque())  # src_ip -> deque of (port, timestamp)

# Tracks login attempts per IP — we store timestamp and whether it looked like a failure
_brute_tracker = defaultdict(lambda: deque())  # src_ip -> deque of (timestamp, is_failure)

# Tracks super fast TCP connection attempts per IP (for catching brute force via connection flood)
_brute_conn_tracker = defaultdict(lambda: deque())  # src_ip -> deque of timestamps

# Tracks how many packets a source sends to a specific destination in a short time (DDoS trigger)
_ddos_tracker = defaultdict(lambda: deque())  # (src, dst) -> deque of timestamps

# Tracks total number of packets sent to a destination regardless of source (volume-based DDoS)
_ddos_total_packets_tracker = defaultdict(lambda: deque())  # dst -> deque of timestamps

# Tracks how many different source IPs are hitting a single destination (unique-source DDoS)
_ddos_unique_sources_tracker = defaultdict(
    lambda: {
        'deque': deque(),                    # List of (src, timestamp) to prune by time
        'counts': defaultdict(int),          # Count how many times each source appeared
        'sources': set()                     # Track which source IPs are active
    }
)  # dst -> {details about sources hitting this dst}

# Tracks repeated connections from a source to multiple destinations (used to catch beaconing)
_cnc_tracker = defaultdict(lambda: defaultdict(lambda: deque()))  # src -> dst -> deque of timestamps

# Tracks how many bytes a source is sending over time (used for exfiltration alerts)
_exfil_tracker = defaultdict(lambda: deque())  # src -> deque of (packet size in bytes, timestamp)

# Keeps track of when we last alerted for each rule so it doesn't spam the same alert too often
_cooldowns = defaultdict(lambda: defaultdict(lambda: 0))  # src -> rule -> last triggered time

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _now() -> float:
    """
    Get the current time using a clock that only moves forward.
    Used to keep track of how long ago something happened.
    """
    return time.monotonic()

def _utc_ts() -> str:
    """
    Get the current time in a readable timestamp format (UTC).
    This is what is put in the alert logs so you know when stuff happened.
    """
    return datetime.now().isoformat() + "Z"

def _prune(q: deque, window: float, now: float):
    """
    Clean out old entries from a list that are older than the time window.
    This keeps memory low and only keeps recent events of importance.
    """
    while q:
        ts = q[0][1] if isinstance(q[0], tuple) else q[0]
        if now - ts > window:
            q.popleft()
        else:
            break

def is_periodic(times: deque) -> bool:
    """
    Check if the same thing keeps happening over and over at a steady pace.
    If it does, it might be a device "phoning home" — common with malware.
    """
    if len(times) < 3:
        return False
    intervals = [t2 - t1 for t1, t2 in zip(times, list(times)[1:])]
    mean_i = statistics.mean(intervals)
    cv = statistics.pstdev(intervals) / mean_i if mean_i else 1
    return cv <= CNC_PERIODIC_CV_MAX

def _ready(rule: str, now: float) -> bool:
    """
    Check if enough time has passed since the last alert for this rule.
    Prevents from spamming the same alert over and over again.
    """
    last = _cooldowns[rule].get('ts', 0)
    return (now - last) >= COOLDOWN_SEC

def _set_cooldown(rule: str, now: float):
    """
    Mark the current time as the last time this rule triggered an alert.
    This way it doesn't alert on the same thing again too soon.
    """
    _cooldowns[rule]['ts'] = now

def _build_alert(
    src: str, dst: str, rule: str, desc: str, severity_label: str
) -> Dict:
    """
    Make an alert that includes all the important details:
    what happened, who did it, who was targeted, how bad it is, and when it happened.
    This gets shown in the dashboard and saved to the alert logs.
    """
    num = SEV_LABEL_TO_NUM.get(severity_label, SEV_LABEL_TO_NUM['unknown'])
    color = SEV_LABEL_TO_COLOR.get(severity_label, SEV_LABEL_TO_COLOR['unknown'])
    alert = {
        "type":           "Behavioral Detection",
        "rule":           rule,
        "description":    desc,
        "src_ip":         src,
        "dst_ip":         dst,
        "timestamp":      _utc_ts(),
        "severity":       num,
        "severity_label": severity_label,
        "color":          color,
        "source":         "Heuristics",
    }
    return alert

def is_streaming_protocol(packet) -> bool:
    """
    Peek inside a UDP packet to see if it looks like it's for video streaming.
    If it is, avoid flagging it as a data exfiltration attempt. 
    Still needs work.
    """
    if not packet.haslayer(Raw) or not packet.haslayer(UDP):
        return False
    try:
        payload = packet[Raw].load.decode('utf-8', 'ignore')
        return bool(re.search(r"(DESCRIBE|PLAY|SETUP|RTSP/)", payload, re.I))
    except:
        return False

# ──────────────────────────────────────────────────────────────────────────────
# Main API
# ──────────────────────────────────────────────────────────────────────────────
def behavioral_detect(packet) -> List[Dict]:
    """
    Checks each packet that comes in to see if anything sketchy is going on.
    Tracks different types of bad behavior like:
      - Port scanning
      - Brute-force login attempts (via payload or TCP flags)
      - Floods (DDoS style attacks, either lots of packets or lots of sources)
      - C2 beaconing (when a device checks in with a remote server on a schedule)
      - Data exfiltration (sending way too much data somewhere it shouldn’t)

    If it spots something off, it creates an alert and logs it for the dashboard.
    Cooldowns help prevent alert spam, and some behavior is skipped if it's known-good streaming.
    """
    alerts: List[Dict] = []
    now = _now()

    # Skip anything without an IP layer (might be ARP or something else)
    if not packet.haslayer(IP):
        return alerts

    src = packet[IP].src
    dst = packet[IP].dst
    pkt_len = len(packet)

    # Use the lock so only one thread can update detection state at a time
    with _lock:

        # ─── 1) Port Scan Detection ────────────────────────────────────────────
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            q = _scan_tracker[src]
            q.append((port, now))          # Log the destination port it just saw
            _prune(q, PORT_SCAN_WINDOW, now)
            unique_ports = {p for p, _ in q}
            if len(unique_ports) >= PORT_SCAN_THRESHOLD and _ready('port_scan', now):
                alerts.append(
                    _build_alert(src, dst, "Port Scanning",
                                 f"{len(unique_ports)} distinct ports in {PORT_SCAN_WINDOW}s",
                                 "medium")
                )
                _set_cooldown('port_scan', now)
                q.clear()  # Reset so it doesn't get duplicates too fast

        # ─── 2) Brute Force Login Detection ───────────────────────────────────
        if packet.haslayer(TCP) and packet[TCP].dport in BRUTE_PORTS:
            # Look inside payload (if it exists) to check for login errors or prompts
            is_fail = False
            is_prompt = False
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    is_fail = bool(re.search(r"(invalid password|login failed|authentication error|permission denied|access denied|failed authentication)", payload, re.I))
                    is_prompt = bool(re.search(r"\b(username|login|password|ssh):\s*\w+", payload, re.I))
                except:
                    pass

            # Track failed/prompt attempts in a queue
            bq = _brute_tracker[src]
            if is_fail or is_prompt:
                bq.append((now, is_fail))
            elif 'S' in packet[TCP].flags or 'R' in packet[TCP].flags:
                bq.append((now, True))  # Treat rapid connections as likely brute attempts

            _prune(bq, BRUTE_FORCE_WINDOW, now)
            fails = sum(1 for t, fail in bq if fail)
            if fails >= BRUTE_FORCE_THRESHOLD and _ready('brute_force', now):
                alerts.append(
                    _build_alert(src, dst, "Brute Force Login",
                                 f"{fails} failed attempts in {BRUTE_FORCE_WINDOW}s", "high")
                )
                _set_cooldown('brute_force', now)
                bq.clear()

            # Now check for rapid TCP connections (brute via volume)
            cq = _brute_conn_tracker[src]
            if 'S' in packet[TCP].flags or 'R' in packet[TCP].flags:
                cq.append(now)
            _prune(cq, BRUTE_CONNECTION_WINDOW, now)
            if len(cq) >= BRUTE_CONNECTION_THRESHOLD and _ready('brute_conn', now):
                alerts.append(
                    _build_alert(src, dst, "Brute Force Connection Attempts",
                                 f"{len(cq)} rapid TCP connections to {dst}:{packet[TCP].dport} in {BRUTE_CONNECTION_WINDOW}s", "high")
                )
                _set_cooldown('brute_conn', now)
                cq.clear()

        # ─── 3) DDoS Flood Detection ──────────────────────────────────────────

        # 3a) Detect too many packets from one source to one destination
        ddq = _ddos_tracker[(src, dst)]
        ddq.append(now)
        _prune(ddq, DDOS_TIME_WINDOW, now)
        if len(ddq) > DDOS_RATE_THRESHOLD and _ready('ddos', now):
            alerts.append(
                _build_alert(src, dst, "DDoS Flood",
                             f"{len(ddq)} packets in {DDOS_TIME_WINDOW}s to {dst}", "critical")
            )
            _set_cooldown('ddos', now)
            ddq.clear()

        # 3b) Detect too many total packets to one destination from any source
        total_tracker = _ddos_total_packets_tracker[dst]
        total_tracker.append(now)
        _prune(total_tracker, DDOS_TIME_WINDOW, now)
        if len(total_tracker) > DDOS_TOTAL_PACKETS_THRESHOLD and _ready('ddos_total', now):
            alerts.append(
                _build_alert("multiple", dst, "DDoS Total Packets",
                             f"{len(total_tracker)} packets in {DDOS_TIME_WINDOW}s to {dst}", "critical")
            )
            _set_cooldown('ddos_total', now)

        # 3c) Detect many unique IPs hitting the same destination
        unique_tracker = _ddos_unique_sources_tracker[dst]
        deque_ = unique_tracker['deque']
        counts = unique_tracker['counts']
        sources = unique_tracker['sources']

        deque_.append((src, now))
        if counts[src] == 0:
            sources.add(src)
        counts[src] += 1

        # Clean out old entries and remove stale IPs
        while deque_ and deque_[0][1] < now - DDOS_TIME_WINDOW:
            old_src, _ = deque_.popleft()
            counts[old_src] -= 1
            if counts[old_src] == 0:
                sources.remove(old_src)
                del counts[old_src]

        if len(sources) > DDOS_UNIQUE_SOURCES_THRESHOLD and _ready('ddos_unique', now):
            alerts.append(
                _build_alert("multiple", dst, "DDoS Unique Sources",
                             f"{len(sources)} unique sources in {DDOS_TIME_WINDOW}s to {dst}", "critical")
            )
            _set_cooldown('ddos_unique', now)

        # ─── 4) C&C Beaconing Detection ───────────────────────────────────────

        # Track connections from src to dst and analyze if it's happening on a schedule
        cncd = _cnc_tracker[src][dst]
        cncd.append(now)

        # Clean up empty hosts
        for peer, times in list(_cnc_tracker[src].items()):
            _prune(times, CNC_TIME_WINDOW, now)
            if not times:
                del _cnc_tracker[src][peer]

        hosts = list(_cnc_tracker[src].keys())
        total = sum(len(t) for t in _cnc_tracker[src].values())
        counts = [len(t) for t in _cnc_tracker[src].values()]

        if (
            0 < len(hosts) <= CNC_HOSTS_MAX
            and total >= CNC_TOTAL_THRESHOLD
            and all(c >= CNC_MIN_PER_HOST for c in counts)
            and any(is_periodic(t) for t in _cnc_tracker[src].values())
            and _ready('cnc', now)
        ):
            periodic = [h for h, t in _cnc_tracker[src].items() if is_periodic(t)]
            alerts.append(
                _build_alert(src, dst, "C&C Beaconing",
                             f"Beaconing to {hosts}, periodic on {periodic}", "medium")
            )
            _set_cooldown('cnc', now)
            _cnc_tracker[src].clear()

        # ─── 5) Data Exfiltration Detection ───────────────────────────────────

        # Figure out if this packet is from something trusted (like a streaming service)
        is_streaming = (
            src in KNOWN_STREAMING_DEVICES or
            (packet.haslayer(UDP) and packet[UDP].dport in STREAMING_PORTS and is_streaming_protocol(packet))
        )
        is_known_destination = False

        # Try to resolve domain name for UDP-based streaming (via DNSQR layer)
        if packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode('utf-8').rstrip('.').lower()
                is_known_destination = any(domain in d for d in KNOWN_STREAMING_DOMAINS)
            except:
                pass

        # Use a lower threshold for unknown traffic, higher for trusted stuff
        threshold = EXFIL_STRICT_THRESHOLD if not (is_streaming or is_known_destination) else EXFIL_VOLUME_THRESHOLD

        # Track how much data src is sending over time
        eq = _exfil_tracker[src]
        eq.append((pkt_len, now))
        _prune(eq, EXFIL_WINDOW_SECONDS, now)
        volume = sum(size for size, _ in eq)

        if volume > threshold and _ready('exfil', now):
            alerts.append(
                _build_alert(src, dst, "Data Exfiltration",
                             f"{volume} bytes sent in {EXFIL_WINDOW_SECONDS}s to {dst}", "high")
            )
            _set_cooldown('exfil', now)
            eq.clear()

    # Log everything detected for this packet
    for al in alerts:
        log_alert(al)

    return alerts
