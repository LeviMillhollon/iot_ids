from __future__ import annotations

import time
import threading
import statistics
import re
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Tuple

from scapy.all import IP, TCP, UDP, Raw  # type: ignore
from scapy.layers.dns import DNSQR       # type: ignore

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

STREAMING_PORTS         = {554, 8554, 3074, 3478}  # RTSP, gaming
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
# ──────────────────────────────────────────────────────────────────────────────
_lock = threading.Lock()
_scan_tracker   = defaultdict(lambda: deque())                  # src_ip -> deque[(port,ts)]
_brute_tracker  = defaultdict(lambda: deque())                  # src_ip -> deque[(ts,is_failure)]
_brute_conn_tracker = defaultdict(lambda: deque())              # src_ip -> deque[ts] for rapid connections
_ddos_tracker   = defaultdict(lambda: deque())                  # (src,dst) -> deque[ts]
_ddos_total_packets_tracker = defaultdict(lambda: deque())      # dst -> deque[ts]
_ddos_unique_sources_tracker = defaultdict(lambda: {'deque': deque(), 'counts': defaultdict(int), 'sources': set()})  # dst -> {'deque': deque[(src,ts)], 'counts': {src: count}, 'sources': set[src]}
_cnc_tracker    = defaultdict(lambda: defaultdict(lambda: deque()))  # src -> dst -> deque[ts]
_exfil_tracker  = defaultdict(lambda: deque())                  # src -> deque[(bytes,ts)]
_cooldowns      = defaultdict(lambda: defaultdict(lambda: 0))   # src -> rule -> last_ts

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _now() -> float:
    return time.monotonic()

def _utc_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _prune(q: deque, window: float, now: float):
    while q:
        ts = q[0][1] if isinstance(q[0], tuple) else q[0]
        if now - ts > window:
            q.popleft()
        else:
            break

def is_periodic(times: deque) -> bool:
    if len(times) < 3:
        return False
    intervals = [t2 - t1 for t1, t2 in zip(times, list(times)[1:])]
    mean_i = statistics.mean(intervals)
    cv = statistics.pstdev(intervals) / mean_i if mean_i else 1
    return cv <= CNC_PERIODIC_CV_MAX

def _ready(rule: str, now: float) -> bool:
    last = _cooldowns[rule].get('ts', 0)
    return (now - last) >= COOLDOWN_SEC

def _set_cooldown(rule: str, now: float):
    _cooldowns[rule]['ts'] = now

def _build_alert(
    src: str, dst: str, rule: str, desc: str, severity_label: str
) -> Dict:
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
    alerts: List[Dict] = []
    now = _now()

    if not packet.haslayer(IP):
        return alerts

    src = packet[IP].src
    dst = packet[IP].dst
    pkt_len = len(packet)

    with _lock:
        # 1) Port scanning
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            q = _scan_tracker[src]
            q.append((port, now))
            _prune(q, PORT_SCAN_WINDOW, now)
            unique_ports = {p for p, _ in q}
            if len(unique_ports) >= PORT_SCAN_THRESHOLD and _ready('port_scan', now):
                alerts.append(
                    _build_alert(src, dst, "Port Scanning",
                                 f"{len(unique_ports)} distinct ports in {PORT_SCAN_WINDOW}s",
                                 "medium")
                )
                _set_cooldown('port_scan', now)
                q.clear()

        # 2) Brute-force login
        if packet.haslayer(TCP) and packet[TCP].dport in BRUTE_PORTS:
            # Payload-based detection
            is_fail = False
            is_prompt = False
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    is_fail = bool(re.search(r"(invalid password|login failed|authentication error|permission denied|access denied|failed authentication)", payload, re.I))
                    is_prompt = bool(re.search(r"\b(username|login|password|ssh):\s*\w+", payload, re.I))
                except Exception as e:
                    payload = ""
            # Connection-based detection
            bq = _brute_tracker[src]
            if is_fail or is_prompt:
                bq.append((now, is_fail))
            elif 'S' in packet[TCP].flags or 'R' in packet[TCP].flags:  # SYN or RST
                bq.append((now, True))  # Count rapid connections as potential failures
            _prune(bq, BRUTE_FORCE_WINDOW, now)
            fails = sum(1 for t, fail in bq if fail)
            if fails >= BRUTE_FORCE_THRESHOLD and _ready('brute_force', now):
                alerts.append(
                    _build_alert(src, dst, "Brute Force Login",
                                 f"{fails} failed attempts in {BRUTE_FORCE_WINDOW}s", "high")
                )
                _set_cooldown('brute_force', now)
                bq.clear()

            # Rapid connection detection
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

        # 3) DDoS flood (per source-destination pair)
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

        # 3a) DDoS flood (total packets to destination)
        total_tracker = _ddos_total_packets_tracker[dst]
        total_tracker.append(now)
        _prune(total_tracker, DDOS_TIME_WINDOW, now)
        if len(total_tracker) > DDOS_TOTAL_PACKETS_THRESHOLD and _ready('ddos_total', now):
            alerts.append(
                _build_alert("multiple", dst, "DDoS Total Packets",
                             f"{len(total_tracker)} packets in {DDOS_TIME_WINDOW}s to {dst}", "critical")
            )
            _set_cooldown('ddos_total', now)

        # 3b) DDoS flood (unique sources to destination)
        unique_tracker = _ddos_unique_sources_tracker[dst]
        deque_ = unique_tracker['deque']
        counts = unique_tracker['counts']
        sources = unique_tracker['sources']
        deque_.append((src, now))
        if counts[src] == 0:
            sources.add(src)
        counts[src] += 1
        while deque_ and deque_[0][1] < now - DDOS_TIME_WINDOW:
            old_src, old_ts = deque_.popleft()
            counts[old_src] -= 1
            if counts[old_src] == 0:
                sources.remove(old_src)
                del counts[old_src]  # Clean up to prevent memory leaks
        if len(sources) > DDOS_UNIQUE_SOURCES_THRESHOLD and _ready('ddos_unique', now):
            alerts.append(
                _build_alert("multiple", dst, "DDoS Unique Sources",
                             f"{len(sources)} unique sources in {DDOS_TIME_WINDOW}s to {dst}", "critical")
            )
            _set_cooldown('ddos_unique', now)

        # 4) C&C beaconing
        cncd = _cnc_tracker[src][dst]
        cncd.append(now)
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

        # 5) Data exfiltration
        is_streaming = (
            src in KNOWN_STREAMING_DEVICES or
            (packet.haslayer(UDP) and packet[UDP].dport in STREAMING_PORTS and is_streaming_protocol(packet))
        )
        is_known_destination = False
        if packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode('utf-8').rstrip('.').lower()
                is_known_destination = any(domain in d for d in KNOWN_STREAMING_DOMAINS)
            except:
                pass
        threshold = EXFIL_STRICT_THRESHOLD if not (is_streaming or is_known_destination) else EXFIL_VOLUME_THRESHOLD
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

    for al in alerts:
        log_alert(al)

    return alerts