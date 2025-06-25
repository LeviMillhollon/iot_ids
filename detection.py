

from signature_engine import signature_detect
#from heuristic_engine import detect as heuristic_detect
#from anomaly_engine import detect as anomaly_detect
from behavioral_engine import behavioral_detect

from logger import log_alert

def run_detections(pkt):
    alerts = []

    for engine in [signature_detect, behavioral_detect]:
        result = engine(pkt)
        if result:
            alerts.extend(result)

    return alerts

