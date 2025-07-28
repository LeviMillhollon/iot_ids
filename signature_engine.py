"""
signature_engine.py

NOTE: signature-based rules are being written directly to Suricata's
YAML rules file for performance reasons. 

──────────────────────────────────────────────────────────────────────────────

Signature-based detection engine
- Looks for raw strings or patterns in payloads (e.g., HTTP, DNS, FTP)
- Triggers alerts with Suricata-style severity scores
- Deduplicates alerts using a cooldown window

Severity mappings (for Suricata compatibility):
    1  High
    2  Medium
    3  Low
    4  Info / Unknown
"""

from __future__ import annotations
import re
from datetime import datetime
from collections import deque
from typing import List

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNSQR
from scapy.packet import Raw
from logger import log_alert  # writes alerts to alerts.jsonl

# ───────────────────────────── Config ─────────────────────────────

SURICATA_SEVERITY = {
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 4,
}

COOLDOWN_SECONDS = 60  # time before duplicate (sig,src) alert can fire again
dedup_state: dict[tuple[str, str], float] = {}  # (signature name, src IP) → timestamp

# ─────────────────────── Signature Definitions ───────────────────────
# These are text patterns to match in raw payloads.
# Format:
#   - name → regex patterns (compiled at load)
#   - description and severity label
#   - optional source and color (for dashboard)

SIGNATURES: dict[str, dict] = {
    "Cleartext Password": {
        "patterns": [r"password=", r"pass=", r"Authorization: Basic", r"login=", r"auth=", r"(?m)^\s*PASS\s+\S+"],
        "description": "Possible transmission of credentials in plaintext (e.g., query strings, HTTP Basic Auth).",
        "source": "OWASP IoT Top 10",
        "severity": "high",
        "color": "red",
    },
    "Telnet Usage": {
        "patterns": [r"\btelnet\b", r"\busername: ", r"\bpassword: "],
        "description": "Telnet is insecure.",
        "source": "Mirai Botnet analysis, NIST SP 800-183",
        "severity": "high",
    },
    "FTP Login": {
        "patterns": [r"\bFTP LOGIN\b",  r"530 Login incorrect", r"(?m)^\s*USER\s+\S+", 
        r"(?m)^\s*PASS\s+\S+", r"(?m)^230\s+Login successful"],
        "description": "FTP sends credentials in plaintext. Often abused by malware.",
        "severity": "medium",
    },
    "Default Credentials": {
        "patterns": [r"admin:admin", r"root:root", r"user:user", r"guest:guest", r"admin:1234", r"admin:password"],
        "description": "Indicators of weak or factory default passwords.",
        "severity": "medium",
    },
    "Remote Shell Execution": {
        "patterns": [ r"/dev/tcp", r"nc -e", r"bash -i", r"/bin/sh", r"/bin/bash", r"cmd.exe", r"powershell.exe"],
        "description": "Likely reverse shell command or shell injection attempt.",
        "severity": "high",
    },
    "Downloads": {
        "patterns": [r"wget http", r"curl http", r"tftp ", r"ftp://", r"http://.*\.bin"],
        "description": "Suspicious file downloads — may indicate payload delivery.",
        "severity": "medium",
        
    },
    "DNS Tunneling": {
        "patterns": [r"[A-Za-z0-9+/=]{20,}\.com", r"dnscat", r"iodine"],
        "description": "Encoded DNS queries often used for tunneling or exfiltration.",
        "severity": "medium",
    },
    "Mirai Botnet": {
        "patterns": [ r"/busybox", r"/bin/busybox"],
        "description": "Mirai malware indicators.",
        "severity": "high",
        "resource": "https://blog.xlab.qianxin.com/mirai-tbot-en/",
    },
    "Gafgyt Botnet": {
        "patterns": [r"tfpget", r"cd /tmp;", r"chmod 777", r"./mozi"],
        "description": "Signs of Gafgyt/Mozi-style botnet payloads.",
        "severity": "high",
        "resource": "https://isc.sans.edu/diary/30390"
    },
    "Suspicious HTTP Payload": {
        "patterns": [r"POST /api/v1/", r"upload", r"token", r"access_key"],
        "description": "Common exfil or C2 REST API requests.",
        "severity": "low",
    },
    "Suspicious SMB": {
        "patterns": [r"\xFF\x53\x4D\x42", r"\x20\x43\x49\x46\x53"],
        "description": "SMB packets — unexpected on most IoT devices.",
        "severity": "low",
    },
}

# Precompile the regexes at load-time for faster matching
COMPILED_SIGS: dict[str, dict] = {
    name: {
        **data,
        "regexes": [re.compile(p, re.IGNORECASE) for p in data.get("patterns", [])],
    }
    for name, data in SIGNATURES.items()
}

# ─────────────────────── Helper Functions ───────────────────────

def _context_slice(buffer: str, match: re.Match, ctx: int = 10) -> str:
    """
    Returns ±10 bytes around the matched pattern, so it can
    show some context in the alert message.
    """
    s, e = match.span()
    return buffer[max(0, s - ctx): min(len(buffer), e + ctx)]

def _suricata_severity(label: str) -> int:
    """
    Convert a human label ('high', 'low', etc.) to Suricata numeric level.
    """
    return SURICATA_SEVERITY.get(label.lower(), 4)

def _build_alert(pkt, sig_name: str, sig_data: dict, context: str, layer: str) -> dict:
    """
    Build a full alert dictionary from the matched packet and signature info.
    This gets logged to alerts.jsonl or passed into the dashboard.
    """
    label = sig_data.get("severity", "unknown")
    return {
        "type": f"{layer} Signature Detection",
        "engine": "signature",
        "rule": sig_name,
        "description": sig_data.get("description", ""),
        "matched_pattern": ", ".join(p.pattern for p in sig_data["regexes"]),
        "matched_content": context,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": _suricata_severity(label),
        "severity_label": label,
        "source": sig_data.get("source", "unspecified"),
        "color": sig_data.get("color", "gray"),
        **(
            {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
            }
            if pkt.haslayer(IP)
            else {}
        ),
        **(
            {
                "src_port": pkt[TCP].sport,
                "dst_port": pkt[TCP].dport,
            }
            if layer == "TCP" and pkt.haslayer(TCP)
            else {}
        ),
        **(
            {
                "query": pkt[DNSQR].qname.decode(errors="ignore"),
            }
            if layer == "DNS" and pkt.haslayer(DNSQR)
            else {}
        ),
    }

# ─────────────────────── Detection Entry Point ───────────────────────

def signature_detect(packet) -> List[dict]:
    """
    The main detection loop.

    - Checks each packet for raw payloads (TCP, UDP, DNS)
    - Tries to match any known signature regexes
    - Returns list of alert dicts (can be empty if nothing matched)
    - Suppresses duplicate alerts from same source within cooldown window
    """
    alerts: list[dict] = []
    now = datetime.utcnow().timestamp()

    def _emit_if_new(sig_name: str, src_ip: str, make_alert):
        # Avoid spammy repeat alerts from same src_ip/signature combo
        key = (sig_name, src_ip)
        if now - dedup_state.get(key, 0) >= COOLDOWN_SECONDS:
            alerts.append(make_alert())
            dedup_state[key] = now

    # Look at raw TCP/UDP payloads (e.g., HTTP, FTP, etc.)
    if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        try:
            payload = bytes(packet[Raw].load).decode("utf-8", "ignore")
        except Exception:
            return alerts  # couldn't decode payload — skip it

        layer = "TCP" if packet.haslayer(TCP) else "UDP"
        src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"

        for sig_name, sig_data in COMPILED_SIGS.items():
            for regex in sig_data["regexes"]:
                if (m := regex.search(payload)):
                    _emit_if_new(
                        sig_name,
                        src_ip,
                        lambda m=m, sig_name=sig_name, sig_data=sig_data: _build_alert(
                            packet, sig_name, sig_data, _context_slice(payload, m), layer
                        ),
                    )
                    break  # only need one match per signature

    # Look at DNS queries too (DNS tunneling, exfil attempts)
    elif packet.haslayer(DNSQR):
        try:
            qname = packet[DNSQR].qname.decode("utf-8", "ignore")
        except Exception:
            return alerts

        src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"

        for sig_name, sig_data in COMPILED_SIGS.items():
            for regex in sig_data["regexes"]:
                if (m := regex.search(qname)):
                    _emit_if_new(
                        sig_name,
                        src_ip,
                        lambda m=m, sig_name=sig_name, sig_data=sig_data: _build_alert(
                            packet, sig_name, sig_data, _context_slice(qname, m), "DNS"
                        ),
                    )
                    break

    return alerts
