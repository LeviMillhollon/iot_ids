# logger.py

import json
import time
import threading
import os
from datetime import datetime

LOG_FILE = "alerts.jsonl"


_lock = threading.Lock()

def log_alert(alert_obj: dict):
    line = json.dumps(alert_obj, default=str)
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


