import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, Raw
AUTH_PORTS = {22, 23, 445, 3389}
SQL_PATTERNS = [
    "' OR 1=1",
    "UNION SELECT",
    "DROP TABLE",
    "--",
    "admin'--",
    "\" OR \"1\"=\"1\"",
]


class PacketCaptureEngine:
    def __init__(self, store, detector, iface=None):
        self.store = store
        self.detector = detector
        self.iface = iface
        self.history = defaultdict(lambda: deque(maxlen=200))

    def start(self):
        print("[*] REAL MODE — Scapy live packet capture starting...")
        print("[*] Listening on all network interfaces...")
        sniff(
            prn=self._process_packet,
            store=False,
            iface=self.iface,
        )

    def _process_packet(self, packet):
        event = self._packet_to_event(packet)
        if event is None:
            return

        self.history[event["src_ip"]].append(event)
        features = self._build_features(event)
        prediction = self.detector.predict(features)

        event["label"] = prediction["label"]
        event["confidence"] = prediction["confidence"]

        if prediction["label"] == "DDoS":
            event["severity"] = "Critical"
        elif prediction["label"] in ("Port Scan", "Brute Force"):
            event["severity"] = "High"
        elif prediction["label"] == "SQL Injection":
            event["severity"] = "Critical"
        else:
            event["severity"] = "Low"

        self.store.add_event(event)

    def _packet_to_event(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = 0
        protocol = "OTHER"
        syn_flag = 0
        payload_text = ""

        if TCP in packet:
            protocol = "TCP"
            dst_port = int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
            syn_flag = 1 if "S" in flags else 0

        elif UDP in packet:
            protocol = "UDP"
            dst_port = int(packet[UDP].dport)

        if Raw in packet:
            try:
                payload_text = bytes(packet[Raw].load).decode(errors="ignore")
            except Exception:
                payload_text = ""

        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": len(packet),
            "payload": payload_text,
            "syn_flag": syn_flag,
            "sql_score": self._sql_score(payload_text),
        }

    def _sql_score(self, payload):
        if not payload:
            return 0
        text = payload.lower()
        score = 0
        for pattern in SQL_PATTERNS:
            if pattern.lower() in text:
                score += 1
        return score

    def _build_features(self, event):
        src_ip = event["src_ip"]
        now = event["timestamp"]

        recent_5  = [x for x in self.history[src_ip] if now - x["timestamp"] <= 5]
        recent_10 = [x for x in self.history[src_ip] if now - x["timestamp"] <= 10]
        recent_30 = [x for x in self.history[src_ip] if now - x["timestamp"] <= 30]

        packets_per_sec = len(recent_5) / 5.0
        unique_ports    = len(set(x["dst_port"] for x in recent_10))
        auth_attempts   = len([x for x in recent_30 if x["dst_port"] in AUTH_PORTS])
        sql_score       = int(event.get("sql_score", 0))
        syn_count       = len([x for x in recent_10 if x.get("syn_flag", 0) == 1])
        syn_ratio       = syn_count / max(1, len(recent_10))

        return [
            float(event["packet_size"]),
            float(packets_per_sec),
            float(unique_ports),
            float(auth_attempts),
            float(sql_score),
            float(syn_ratio),
        ]