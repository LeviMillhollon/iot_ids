from logger import log_alert

# Dummy example for now
def run_ids(pkt, profile=None):
    src_ip = pkt["src_ip"]
    vendor = (profile or {}).get("vendor", "").lower()
    device_type = (profile or {}).get("device_type", "unknown")

    # SAMPLE TEST RULE: Detect Samsung device traffic
    if "samsung" in vendor:
        log_alert({
            "rule": "samsung_tv_traffic",
            "src_ip": src_ip,
            "device_type": device_type,
            "details": "Traffic detected from Samsung TV"
        })