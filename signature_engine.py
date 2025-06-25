import re
from scapy.all import TCP, UDP, Raw, IP, DNS, DNSQR
from logger import log_alert
from datetime import datetime


SIGNATURES = {
   
   
    # Cleartext credentials in HTTP/GET/POST headers or query strings
    "Cleartext Password": {
        "patterns": [r"password=", r"pwd=", r"pass=", r"Authorization: Basic", r"login=", r"auth="],
        "description": "Possible transmission of credentials in plaintext (e.g., query strings, HTTP Basic Auth).",
        "source": "OWASP IoT Top 10",
        "severity": "high",
        "color": "red"
    },
  

    "Telnet Usage": {
        "patterns": [r"\btelnet\b", r"\b23\s", r"\busername: ", r"\bpassword: "],
        "description": "Telnet is insecure, and its presence indicates a serious security misconfiguration.",
        "source": "Mirai Botnet analysis, NIST SP 800-183"
    },

    "FTP Login": {
        "patterns": [r"USER ", r"PASS ", r"\bftp\b", r"530 Login incorrect"],
    # ⬩ Description: FTP sends credentials in plaintext. Often abused by malware for propagation or data exfil.
    # ⬩ Sources: CERT FTP advisories, Wireshark FTP dissector
    },

    "Default Credentials": {
        "patterns": [r"admin:admin", r"root:root", r"user:user", r"guest:guest", r"1234", r"admin:1234", "admin:password"],

    # ⬩ Description: Indicators of weak or factory default passwords — frequently abused in IoT compromise.
    # ⬩ Sources: OWASP IoT Top 10 [Insecure Defaults], Shodan reports, CVEs (e.g., CVE-2016-10401)
    },

    "Remote Shell Execution": {
        "patterns": [r"nc -e", r"bash -i", r"/bin/sh", r"/bin/bash", r"cmd.exe", r"powershell.exe"],
    # ⬩ Description: Command injection via reverse shell payloads.
    # ⬩ Sources: GTFOBins, MITRE ATT&CK T1059 (Command and Scripting Interpreter)
    },

    "Malicious Download": {
        "patterns": [r"wget http", r"curl http", r"tftp ", r"ftp://", r"http://.*\.bin"],
    # ⬩ Description: Signatures for file downloads, often seen in botnet propagation.
    # ⬩ Sources: Mirai/Gafgyt source code leaks, Suricata rules
    },

    "DNS Tunneling": {
        "patterns": [r"[A-Za-z0-9+/=]{20,}\.com", r"dnscat", r"iodine"],
    # ⬩ Description: Long encoded subdomains used for covert data exfiltration.
    # ⬩ Sources: Academic papers on DNS exfiltration, DNSCat2/Iodine tools
    },

    "Mirai Botnet": {
        "patterns": [r"/shell", r"/busybox", r"/bin/busybox", r"Content-Length: 109"],
    # ⬩ Description: Hardcoded commands and indicators from Mirai infection payloads.
    # ⬩ Sources: [Source Code Leak](https://github.com/jgamblin/Mirai-Source-Code), MalwareMustDie
    },

    "Gafgyt Botnet":{
        "patterns": [r"tftp -g", r"cd /tmp;", r"chmod \+x", r"./mozi"],
    # ⬩ Description: TFTP-based propagation typical of Gafgyt/Mozi family.
    # ⬩ Sources: [Mozi Report](https://blog.netlab.360.com/mozi-another-botnet-using-dht/), CVE advisories
    },

    "Suspicious HTTP Payload": {
        "patterns": [r"POST /api/v1/", r"upload", r"token", r"access_key"],
    # ⬩ Description: Common REST API endpoints used in data exfiltration or C2.
    # ⬩ Sources: Wireshark, ThreatPost API abuse studies
    },

    "Suspicious SMB": {
        "patterns": [r"\xFF\x53\x4D\x42", r"\x20\x43\x49\x46\x53"],
    # ⬩ Description: SMB/CIFS traffic rarely appears on IoT devices unless being exploited.
    # ⬩ Sources: EternalBlue exploit (MS17-010), MITRE ATT&CK T1021
    }
}

                    
def signature_detect(packet):
    alerts = []

    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
        except Exception:
            return alerts


        for sig_name, sig_data in SIGNATURES.items():
            if not isinstance(sig_data, dict):
                continue
            patterns = sig_data.get("patterns", [])
            for pattern in patterns:
                try:
                    match = re.search(pattern, payload, re.IGNORECASE)
                    if match:
                        context = extract_match_context(qname, match, context_len=10)
                        rule = {

                            "type": "TCP Signature Detection",
                            "engine": "signature",
                            "rule": sig_name,
                            "description": sig_data.get("description", "no description"),
                            "matched_pattern": pattern,
                            "matched_content": match.group(0),
                            "matched_content": context,
                            "src_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                            "dst_ip": packet[IP].dst if packet.haslayer(IP) else "Unknown",
                            "src_port": packet[TCP].sport,
                            "dst_port": packet[TCP].dport,
                            "flags": str(packet[TCP].flags),
                            "payload_snippet": payload[:100],
                            "timestamp": datetime.now().isoformat(),
                            "severity": sig_data.get("severity", "unknown"),
                            "source": sig_data.get("source", "unspecified"),
                            "color": sig_data.get("color", "gray")
                        }
                        alerts.append(rule)
                        #log_alert(rule)
                except Exception:
                    continue        

    elif packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode(errors="ignore")
        for sig_name, sig_data in SIGNATURES.items():
            if not isinstance(sig_data, dict):
                continue
            patterns = sig_data.get("patterns", [])
            for pattern in patterns:
                try:
                    match = re.search(pattern, qname, re.IGNORECASE)
                    if match:
                        context = extract_match_context(qname, match, context_len=10)
                        rule = {
                            "type": "DNS Signature Detection",
                            "engine": "signature",
                            "rule": sig_name,
                            "description": sig_data.get("description", "no description"),
                            "matched_pattern": pattern,
                            "matched_content": match.group(0),
                            "matched_content": context,
                            "src_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                            "dst_ip": packet[IP].dst if packet.haslayer(IP) else "Unknown",
                            "query": qname,
                            "timestamp": datetime.now().isoformat(),
                            "severity": sig_data.get("severity", "unknown"),
                            "source": sig_data.get("source", "unspecified"),
                            "color": sig_data.get("color", "gray")
                        }
                        alerts.append(rule)
                        #log_alert(rule)
                except Exception:
                    continue        

    return alerts

def extract_match_context(text: str, match, context_len: int = 10):
    start, end = match.start(), match.end()
    ctx_start = max(0, start - context_len)
    ctx_end   = min(len(text), end + context_len)
    # the slice will include context + the match itself
    return text[ctx_start:ctx_end]



