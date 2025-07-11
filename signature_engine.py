"""Signature‑based detection engine
Adapted to output Suricata‑compatible numeric severities (1‑4).
Suricata mapping:
    1 – **High**
    2 – **Medium**
    3 – **Low**
    4 – **Info / Unknown**
"""

from __future__ import annotations

import re
from datetime import datetime
from collections import deque
from typing import List

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNSQR
from scapy.packet import Raw

from logger import log_alert  # local util to write alerts as JSONL

# ---------------------------------------------------------------------------
# ⚙️ Config
# ---------------------------------------------------------------------------

SURICATA_SEVERITY = {
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 4,
}

COOLDOWN_SECONDS = 60  # suppress duplicate (sig,src) alerts inside this window

dedup_state: dict[tuple[str, str], float] = {}  # (sig_name, src_ip) -> last_ts

# ---------------------------------------------------------------------------
# ✨  Signature definitions
# ---------------------------------------------------------------------------

# NOTE: keep *string* labels; we convert to numeric when emitting the alert.
#       That makes it friendlier to tweak in YAML/JSON later if you externalise.
SIGNATURES: dict[str, dict] = {
    "Cleartext Password": {
        "patterns": [r"password=", r"pwd=", r"pass=", r"Authorization: Basic", r"login=", r"auth="],
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
        "patterns": [r"USER ", r"PASS ", r"\bFTP LOGIN\b", r"530 Login incorrect"],
        "description": "FTP sends credentials in plaintext. Often abused by malware for propagation or data exfil.",
        "severity": "medium",
    },
    "Default Credentials": {
        "patterns": [
            r"admin:admin",
            r"root:root",
            r"user:user",
            r"guest:guest",
            r"1234",
            r"admin:1234",
            r"admin:password",
        ],
        "description": "Indicators of weak or factory default passwords — frequently abused in IoT compromise.",
        "severity": "medium",
    },
    "Remote Shell Execution": {
        "patterns": [r"nc -e", r"bash -i", r"/bin/sh", r"/bin/bash", r"cmd.exe", r"powershell.exe"],
        "description": "Command injection via reverse shell payloads.",
        "severity": "high",
    },
    "Malicious Download": {
        "patterns": [r"wget http", r"curl http", r"tftp ", r"ftp://", r"http://.*\.bin"],
        "description": "Signatures for file downloads, often seen in botnet propagation.",
        "severity": "medium",
    },
    "DNS Tunneling": {
        "patterns": [r"[A-Za-z0-9+/=]{20,}\.com", r"dnscat", r"iodine"],
        "description": "Long encoded subdomains used for covert data exfiltration.",
        "severity": "medium",
    },
    "Mirai Botnet": {
        "patterns": [r"/shell", r"/busybox", r"/bin/busybox", r"Content-Length: 109"],
        "description": "Hardcoded commands and indicators from Mirai infection payloads.",
        "severity": "high",
    },
    "Gafgyt Botnet": {
        "patterns": [r"tftp -g", r"cd /tmp;", r"chmod \+x", r"./mozi"],
        "description": "TFTP-based propagation typical of Gafgyt/Mozi family.",
        "severity": "high",
    },
    "Suspicious HTTP Payload": {
        "patterns": [r"POST /api/v1/", r"upload", r"token", r"access_key"],
        "description": "Common REST API endpoints used in data exfiltration or C2.",
        "severity": "low",
    },
    "Suspicious SMB": {
        "patterns": [r"\xFF\x53\x4D\x42", r"\x20\x43\x49\x46\x53"],
        "description": "SMB/CIFS traffic rarely appears on IoT devices unless being exploited.",
        "severity": "low",
    },
}

# Pre‑compile regexes once at import time for speed
COMPILED_SIGS: dict[str, dict] = {
    name: {
        **data,
        "regexes": [re.compile(p, re.IGNORECASE) for p in data.get("patterns", [])],
    }
    for name, data in SIGNATURES.items()
}

# ---------------------------------------------------------------------------
# 🔎  Helpers
# ---------------------------------------------------------------------------

def _context_slice(buffer: str, match: re.Match, ctx: int = 10) -> str:
    """Return ±ctx‑byte context around the regex match."""
    s, e = match.span()
    return buffer[max(0, s - ctx) : min(len(buffer), e + ctx)]


def _suricata_severity(label: str) -> int:
    return SURICATA_SEVERITY.get(label.lower(), 4)


def _build_alert(pkt, sig_name: str, sig_data: dict, context: str, layer: str) -> dict:
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

# ---------------------------------------------------------------------------
# 🚨  Detection main entry
# ---------------------------------------------------------------------------

def signature_detect(packet) -> List[dict]:
    """Inspect *packet* for signature hits. Return list of alert dicts."""
    alerts: list[dict] = []
    now = datetime.utcnow().timestamp()

    def _emit_if_new(sig_name: str, src_ip: str, make_alert):
        key = (sig_name, src_ip)
        if now - dedup_state.get(key, 0) >= COOLDOWN_SECONDS:
            alerts.append(make_alert())
            dedup_state[key] = now

    # --- TCP/UDP payloads --------------------------------------------------
    if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        try:
            payload = bytes(packet[Raw].load).decode("utf-8", "ignore")
        except Exception:
            return alerts  # binary payload; bail early

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
                    break  # stop at first pattern match per signature

    # --- DNS queries -------------------------------------------------------
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

    # ----------------------------------------------------------------------
    return alerts