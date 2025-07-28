"""
detection.py

This used to be the central controller for running all detection engines:
- signature_detect
- anomaly_detect (experimental)
- behavioral_detect (flow-based heuristics)

Right now, only the behavioral engine is active. This file still 
exists as a placeholder in case I reintroduce multi-engine support later.

Note: `run_detections()` is currently down. It now calls behavioral_detect() 
directly from main.py for simplicity and speed.
"""

# from signature_engine import signature_detect
# from heuristic_engine import detect as heuristic_detect
# from anomaly_engine import detect as anomaly_detect

from behavioral_engine import behavioral_detect
from logger import log_alert

# This wrapper is disabled for now.
# Left here for future use if to re-enable multi-engine detection.
def run_detections(pkt):
    alerts = []

    # Previously looped through all active detection engines
    for engine in [behavioral_detect]:  
        result = engine(pkt)
        if result:
            alerts.extend(result)

    return alerts