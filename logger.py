# logger.py

import json
import time
import threading

LOG_FILE = "alerts.jsonl"
_lock = threading.Lock()

def log_alert(alert_obj: dict):
    """
    Append an alert to alerts.jsonl.
    Automatically adds a UNIX timestamp field.
    """
    # Add timestamp if not provided
    if "timestamp" not in alert_obj:
        alert_obj["timestamp"] = time.time()

    line = json.dumps(alert_obj)
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
