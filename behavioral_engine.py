
# behavioral_engine.py

import time
import statistics
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import IP, TCP, UDP
from logger import log_alert

# Configurable thresholds
PORT_SCAN_THRESHOLD = 10       # number of unique ports per IP
PORT_SCAN_WINDOW    = 60       # seconds

BRUTE_FORCE_THRESHOLD = 5      # failed login attempts
BRUTE_FORCE_WINDOW    = 60     # seconds

DDOS_RATE_THRESHOLD = 600       # packets
DDOS_TIME_WINDOW    = 1       # seconds

CNC_CONTACTS_THRESHOLD = 10    # total contacts
CNC_TOTAL_THRESHOLD   = 10       # total contacts across hosts
CNC_MIN_PER_HOST      = 5        # min contacts per host
CNC_HOSTS_MAX         = 3        # max distinct hosts
CNC_TIME_WINDOW       = 60       # seconds
CNC_PERIODIC_CV_MAX   = 0.5      # max coeff of variation for periodicity


# In-memory trackers
scan_tracker   = defaultdict(lambda: deque())
brute_tracker  = defaultdict(lambda: deque())
ddos_tracker   = defaultdict(lambda: deque())
cnc_tracker    = defaultdict(lambda: defaultdict(lambda: deque()))

def is_periodic(timestamps):
    """Return True if timestamps intervals have low variance (C&C beaconing)."""
    if len(timestamps) < 3:
        return False
    intervals = [t2 - t1 for t1, t2 in zip(timestamps, list(timestamps)[1:])]
    mean_i = statistics.mean(intervals)
    cv = statistics.pstdev(intervals) / mean_i if mean_i else 1
    return cv <= CNC_PERIODIC_CV_MAX


def behavioral_detect(packet):
    """Detect behavioral anomalies: port scan, brute-force, DDoS, C&C beaconing."""
    alerts = []
    now = time.time()

    if not packet.haslayer(IP):
        return alerts

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # --- Port scan detection ---
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        scan_tracker[src_ip].append((dst_port, now))
        # prune old
        while scan_tracker[src_ip] and now - scan_tracker[src_ip][0][1] > PORT_SCAN_WINDOW:
            scan_tracker[src_ip].popleft()
        unique_ports = {p for p, t in scan_tracker[src_ip]}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "Behavioral Detection",
                "rule": "Port Scanning",
                "description": f"Detected port scanning from {src_ip} to {len(unique_ports)} ports.",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": datetime.now().isoformat(),
                "severity": "medium",
                "source": "Heuristics",
                "color": "orange"
            })
            scan_tracker[src_ip].clear()

    # --- Brute-force login detection ---
    if packet.haslayer(TCP) and hasattr(packet, 'load'):
        try:
            payload = packet.load.decode(errors="ignore").lower()
            if any(k in payload for k in ("login", "username", "password")):
                brute_tracker[src_ip].append(now)
                while brute_tracker[src_ip] and now - brute_tracker[src_ip][0] > BRUTE_FORCE_WINDOW:
                    brute_tracker[src_ip].popleft()
                if len(brute_tracker[src_ip]) >= BRUTE_FORCE_THRESHOLD:
                    alerts.append({
                        "type": "Behavioral Detection",
                        "rule": "Brute Force Login Attempt",
                        "description": f"Brute-force login detected from {src_ip}.",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": datetime.now().isoformat(),
                        "severity": "high",
                        "source": "Heuristics",
                        "color": "red"
                    })
                    brute_tracker[src_ip].clear()
        except Exception:
            pass

    # --- DDoS flood detection ---
    key = (src_ip, dst_ip)
    ddos_tracker[key].append(now)
    while ddos_tracker[key] and now - ddos_tracker[key][0] > DDOS_TIME_WINDOW:
        ddos_tracker[key].popleft()
    if len(ddos_tracker[key]) > DDOS_RATE_THRESHOLD:
        alerts.append({
            "type": "Behavioral Detection",
            "rule": "DDoS Flood",
            "description": f"High packet rate from {src_ip} to {dst_ip}: {len(ddos_tracker[key])} pkts/{DDOS_TIME_WINDOW}s.",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "timestamp": datetime.now().isoformat(),
            "severity": "critical",
            "source": "Heuristics",
            "color": "red"
        })
        ddos_tracker[key].clear()

    # --- C&C beaconing detection ---
     # Track contact times per host
    cnc_tracker[src_ip][dst_ip].append(now)
    # prune and cleanup
    for host in list(cnc_tracker[src_ip]):
        times = deque(t for t in cnc_tracker[src_ip][host] if now - t <= CNC_TIME_WINDOW)
        if times:
            cnc_tracker[src_ip][host] = times
        else:
            del cnc_tracker[src_ip][host]

    unique_hosts   = list(cnc_tracker[src_ip].keys())
    total_contacts = sum(len(q) for q in cnc_tracker[src_ip].values())
    per_host_counts = [len(q) for q in cnc_tracker[src_ip].values()]

    # Decide beaconing: few hosts, enough volume, per-host threshold, and periodicity
    if (
        len(unique_hosts) <= CNC_HOSTS_MAX and
        total_contacts >= CNC_TOTAL_THRESHOLD and
        all(count >= CNC_MIN_PER_HOST for count in per_host_counts) and
        any(is_periodic(q) for q in cnc_tracker[src_ip].values())
    ):
        alerts.append({
            "type": "Behavioral Detection",
            "rule": "Possible C&C Beaconing",
            "description": (
                f"C&C beaconing from {src_ip} to hosts {unique_hosts}; "
                f"periodic: {[h for h, q in cnc_tracker[src_ip].items() if is_periodic(q)]}"
            ),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "timestamp": datetime.now().isoformat(),
            "severity": "medium",
            "source": "Heuristics",
            "color": "orange"
        })
        cnc_tracker[src_ip].clear()

    return alerts

