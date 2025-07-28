"""
classifier.py

Guesses what kind of device we're looking at (camera, TV, router, etc.)
based on vendor strings, hostnames, and open ports. 

This gets used when devices connect to the HomeIDS AP — we want to 
know what they are so we can prioritize alerts or tune scanning behavior.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple, Dict, Set, Optional


# ─────────────────────────────────────────────────────────────────────────────
# List of all device types we might assign
# ─────────────────────────────────────────────────────────────────────────────
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
    FRAMEO = "frameo"
    UNKNOWN = "Unknown"  # fallback if we can't tell


# ─────────────────────────────────────────────────────────────────────────────
# What is returned after classifying a device
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ClassificationResult:
    device_type: DeviceType    # Best guess on what kind of device this is
    confidence: float          # Normalized score between 0.0 and 1.0
    label: str                 # 'High', 'Moderate', 'Low', or 'None'


class Classifier:
    # ─────────────────────────────────────────────────────────────────────────
    # Words to look for in vendor name or DNS name to help ID device type
    # ─────────────────────────────────────────────────────────────────────────
    KEYWORDS: Dict[DeviceType, Set[str]] = {
        DeviceType.CAMERA: {"hikvision", "shenzhen", "dahua", "reolink", "wyze", "arlo", "nest", "ezviz",
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
        DeviceType.FRAMEO: {},  # no known keywords, port only
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Port numbers that are strong hints toward specific device types
    # ─────────────────────────────────────────────────────────────────────────
    PORT_PREFERENCES: Dict[DeviceType, List[int]] = {
        DeviceType.CAMERA: [554, 8554, 1935, 37777],            # RTSP, RTMP, DVR
        DeviceType.TV: [8009, 8008, 3689, 49152],               # Chromecast, DLNA
        DeviceType.PRINTER: [9100, 631, 515, 9220],             # IPP, JetDirect, LPD
        DeviceType.ROUTER: [53, 8291],                          # DNS, Mikrotik Winbox
        DeviceType.CELL_PHONE: [62078, 5223, 5228],             # Apple sync, push services
        DeviceType.FRAMEO: [37406],                             # Frameo,
        DeviceType.LISTENING_DEVICE: [4070, 55442],             # Spotify/Alexa, Amazon Echo
        DeviceType.GAME_CONSOLE: [2869, 3074, 3478],            # Xbox Live, STUN/TURN
    }

    # ─────────────────────────────────────────────────────────────────────────
    # How confident it needs to be to say something is High or Moderate
    # ─────────────────────────────────────────────────────────────────────────
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
        Try to figure out what kind of device this is.

        It checks the vendor name, the DNS hostname, and the list of open ports.
        If they match known keywords or port signatures, it adds up points and 
        picks the best-matching category.

        Args:
            vendor     – brand name or MAC vendor (e.g., "Hikvision", "Apple")
            dns_name   – hostname if available (e.g., "roku-box.local")
            open_ports – list of open TCP/UDP ports from Nmap

        Returns:
            A ClassificationResult object with the guessed device type,
            a confidence score (0–1), and a label (High, Moderate, Low).
        """
        open_ports = open_ports or []
        fields = [vendor, dns_name or '']
        lowered = [f.lower() for f in fields if f]  # lowercase for matching

        # Step 1: Count matches for each device type
        raw_scores: Dict[DeviceType, int] = {}
        for dtype, keywords in cls.KEYWORDS.items():
            key_score = sum(1 for term in keywords for f in lowered if term in f)
            port_score = sum(1 for port in cls.PORT_PREFERENCES.get(dtype, []) if port in open_ports)
            raw_scores[dtype] = key_score + port_score  # more hits = better match

        # Step 2: If nothing matched, return UNKNOWN
        max_raw = max(raw_scores.values(), default=0)
        if max_raw == 0:
            return ClassificationResult(DeviceType.UNKNOWN, 0.0, 'None')

        # Step 3: Normalize scores so the best one is 1.0
        normalized = {dtype: round(score / max_raw, 2) for dtype, score in raw_scores.items()}
        best_type = max(normalized, key=normalized.get)
        confidence = normalized[best_type]

        # Step 4: Map score to label
        if confidence >= cls.THRESHOLDS['high']:
            label = 'High'
        elif confidence >= cls.THRESHOLDS['moderate']:
            label = 'Moderate'
        else:
            label = 'Low'

        return ClassificationResult(best_type, confidence, label)
