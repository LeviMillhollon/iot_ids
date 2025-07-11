"""behavioral_engine.py

Heuristic detection for:
 - Port scans
 - Brute-force login attempts
 - DDoS floods
 - C&C beaconing
 - Data exfiltration

All alerts use Suricata‐style numeric severity (1–4) plus CSS color mapping.
"""

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
PORT_SCAN_THRESHOLD     = 10    # unique dest ports
PORT_SCAN_WINDOW        = 60    # seconds

BRUTE_FORCE_THRESHOLD   = 5     # failures
BRUTE_FORCE_WINDOW      = 60    # seconds
BRUTE_PORTS             = {22, 23, 80, 443}

DDOS_RATE_THRESHOLD     = 600   # packets
DDOS_TIME_WINDOW        = 1     # second

CNC_TOTAL_THRESHOLD     = 10    # total hits
CNC_MIN_PER_HOST        = 5     # per distinct host
CNC_HOSTS_MAX           = 3     # distinct dst hosts
CNC_TIME_WINDOW         = 60    # seconds
CNC_PERIODIC_CV_MAX     = 0.5   # coefficient of variation

EXFIL_VOLUME_THRESHOLD  = 1_000_000  # bytes
EXFIL_WINDOW_SECONDS    = 60

# Dedup cooldowns
COOLDOWN_SEC = 120  # fallback for behavioral detections

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
_ddos_tracker   = defaultdict(lambda: deque())                  # (src,dst) -> deque[ts]
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

def _get_cooldown(rule: str) -> float:
    return _cooldowns[rule].get('cooldown', COOLDOWN_SEC)

def _set_cooldown(rule: str, now: float):
    _cooldowns[rule]['ts'] = now

def _ready(rule: str, now: float) -> bool:
    last = _cooldowns[rule].get('ts', 0)
    return (now - last) >= COOLDOWN_SEC

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
        if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport in BRUTE_PORTS:
            try:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
            except:
                payload = ""
            is_fail = bool(re.search(r"(invalid password|login failed|authentication error)", payload, re.I))
            is_prompt = bool(re.search(r"\b(username|login):\s*\w+", payload, re.I))
            if is_fail or is_prompt:
                bq = _brute_tracker[src]
                bq.append((now, is_fail))
                _prune(bq, BRUTE_FORCE_WINDOW, now)
                fails = sum(1 for t, fail in bq if fail)
                if fails >= BRUTE_FORCE_THRESHOLD and _ready('brute_force', now):
                    alerts.append(
                        _build_alert(src, dst, "Brute Force Login",
                                     f"{fails} failed attempts in {BRUTE_FORCE_WINDOW}s", "high")
                    )
                    _set_cooldown('brute_force', now)
                    bq.clear()

        # 3) DDoS flood
        ddq = _ddos_tracker[(src, dst)]
        ddq.append(now)
        _prune(ddq, DDOS_TIME_WINDOW, now)
        if len(ddq) > DDOS_RATE_THRESHOLD and _ready('ddos', now):
            alerts.append(
                _build_alert(src, dst, "DDoS Flood",
                             f"{len(ddq)} pkts/sec to {dst}", "critical")
            )
            _set_cooldown('ddos', now)
            ddq.clear()

        # 4) C&C beaconing
        cncd = _cnc_tracker[src][dst]
        cncd.append(now)
        # prune all peers and check conditions
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
        eq = _exfil_tracker[src]
        eq.append((pkt_len, now))
        _prune(eq, EXFIL_WINDOW_SECONDS, now)
        volume = sum(size for size, _ in eq)
        if volume > EXFIL_VOLUME_THRESHOLD and _ready('exfil', now):
            alerts.append(
                _build_alert(src, dst, "Data Exfiltration",
                             f"{volume} bytes sent in {EXFIL_WINDOW_SECONDS}s", "high")
            )
            _set_cooldown('exfil', now)
            eq.clear()

    # emit
    for al in alerts:
        log_alert(al)

    return alerts
