### classifier.py
"""
Classification logic for IoT devices: vendor/port heuristics to determine type and confidence.
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple, Dict, Set, Optional


class DeviceType(Enum):
    CAMERA = "Camera"
    TV = "TV"
    LISTENING_DEVICE = "Listening Device"
    CELL_PHONE = "Cell Phone"
    PRINTER = "Printer"
    ROUTER = "Router"
    COMPUTER = "Computer"
    GAME_CONSOLE = "Game Console"
    SOUND = "Sound"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class ClassificationResult:
    device_type: DeviceType
    confidence: float  # normalized between 0.0 and 1.0
    label: str         # High, Moderate, Low, or None


class Classifier:
    # Keyword sets for classification
    KEYWORDS: Dict[DeviceType, Set[str]] = {
        DeviceType.CAMERA: {"hikvision", "dahua", "reolink", "wyze", "arlo", "nest", "ezviz",
                            "ring", "amcrest", "uniview", "logitech", "vtech"},
        DeviceType.TV: {"samsung", "lg", "sony", "vizio", "tcl", "hisense", "panasonic",
                        "sharp", "philips", "roku", "gaoshengda", "hui"},
        DeviceType.LISTENING_DEVICE: {"amazon", "sonos", "xiaomi", "baidu", "alexa",
                                      "homepod", "echo"},
        DeviceType.CELL_PHONE: {"apple", "iphone", "samsung", "huawei", "xiaomi", "oneplus", "pixel",
                                "motorola", "nokia", "oppo", "vivo", "s20"},
        DeviceType.PRINTER: {"hp", "brother", "epson", "canon", "ricoh", "kyocera", "xerox", "lexmark"},
        DeviceType.ROUTER: {"router", "access point", "gateway", "fios", "xfinity", "netgear", "asus",
                            "tplink", "tp-link", "dlink", "d-link", "linksys", "arris", "orbi", "google"},
        DeviceType.COMPUTER: {"windows", "macbook", "ubuntu", "debian", "linux", "pc", "desktop", "laptop", "intel",
                              "kali", "raspberry", "mbp", "apple"},
        DeviceType.GAME_CONSOLE: {"xbox", "playstation", "nintendo", "switch", "hon hai"},
        DeviceType.SOUND: {"rest"},
    }

    # Port-based heuristics
    PORT_PREFERENCES: Dict[DeviceType, List[int]] = {
        DeviceType.CAMERA: [554],         # RTSP
        DeviceType.TV: [8009],            # Chromecast
        DeviceType.PRINTER: [9100],       # JetDirect
        DeviceType.ROUTER: [53],          # DNS
        DeviceType.CELL_PHONE: [62078],
    }

    # Confidence thresholds
    THRESHOLDS: Dict[str, float] = {
        'high': 0.85,
        'moderate': 0.5,
    }

    @classmethod
    def classify_device(
        cls,
        vendor: str,
        dns_name: Optional[str] = None,
        open_ports: Optional[List[int]] = None
    ) -> ClassificationResult:
        """
        Classify device type with a normalized confidence and label.

        :param vendor: Vendor string from fingerprinting
        :param dns_name: DNS hostname
        :param open_ports: List of open TCP/UDP ports
        :return: ClassificationResult
        """
        open_ports = open_ports or []
        fields = [vendor, dns_name or '',]
        lowered = [f.lower() for f in fields if f]

        # Score each type based on keywords
        raw_scores: Dict[DeviceType, int] = {}
        for dtype, keywords in cls.KEYWORDS.items():
            key_score = sum(1 for term in keywords for f in lowered if term in f)
            port_score = sum(1 for port in cls.PORT_PREFERENCES.get(dtype, []) if port in open_ports)
            raw_scores[dtype] = key_score + port_score

        # Determine max raw score
        max_raw = max(raw_scores.values(), default=0)
        if max_raw == 0:
            return ClassificationResult(DeviceType.UNKNOWN, 0.0, 'None')

        # Normalize and pick best
        normalized = {dtype: round(score / max_raw, 2) for dtype, score in raw_scores.items()}
        best_type = max(normalized, key=normalized.get)
        confidence = normalized[best_type]

        # Label mapping
        if confidence >= cls.THRESHOLDS['high']:
            label = 'High'
        elif confidence >= cls.THRESHOLDS['moderate']:
            label = 'Moderate'
        else:
            label = 'Low'

        return ClassificationResult(best_type, confidence, label)
