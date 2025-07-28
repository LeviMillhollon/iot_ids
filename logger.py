# logger.py
#
# Simple alert logger.
# Writes each alert (as a JSON object) to a line-delimited file.
# Thread-safe using a lock so background threads don’t collide.

import json
import time
import threading
import os
from datetime import datetime

LOG_FILE = "alerts.jsonl"  # All alerts get appended here

_lock = threading.Lock()  # So threads don’t stomp on each other during writes

def log_alert(alert_obj: dict):
    """
    Appends an alert to the log file as a JSON line.

    This is used by all engines (behavioral, Suricata, etc.) to
    record triggered alerts. Alerts are structured dicts with
    keys like src_ip, rule, timestamp, etc.

    This function is thread-safe — uses a lock to avoid race conditions
    when multiple alerts get triggered at once.
    """
    line = json.dumps(alert_obj, default=str)
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
