import os
import json
import time
from collections import defaultdict, deque
from threading import Lock


class IDSStore:
    def __init__(self, log_path="logs/attacks.log"):
        self.lock = Lock()
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        self.total_packets = 0
        self.normal_packets = 0
        self.total_attacks = 0

        self.attack_counts = defaultdict(int)
        self.source_counts = defaultdict(int)

        self.recent_attacks = deque(maxlen=15)
        self.packet_timeline = defaultdict(int)

    def add_event(self, event):
        with self.lock:
            ts = float(event.get("timestamp", time.time()))
            sec = int(ts)

            self.total_packets += 1
            self.packet_timeline[sec] += 1

            src_ip = event.get("src_ip", "unknown")
            self.source_counts[src_ip] += 1

            label = event.get("label", "Normal")

            if label == "Normal":
                self.normal_packets += 1
            else:
                self.total_attacks += 1
                self.attack_counts[label] += 1

                attack_row = {
                    "time": time.strftime("%H:%M:%S", time.localtime(ts)),
                    "src_ip": src_ip,
                    "dst_ip": event.get("dst_ip", "-"),
                    "dst_port": event.get("dst_port", "-"),
                    "attack_type": label,
                    "confidence": event.get("confidence", 0),
                    "severity": event.get("severity", "Medium"),
                }
                self.recent_attacks.appendleft(attack_row)
                self._write_log(attack_row)

            self._prune_timeline()

    def _prune_timeline(self, window=60):
        cutoff = int(time.time()) - window
        old_keys = [k for k in self.packet_timeline.keys() if k < cutoff]
        for k in old_keys:
            del self.packet_timeline[k]

    def _write_log(self, row):
        line = json.dumps(row, ensure_ascii=False)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def snapshot(self):
        with self.lock:
            now = int(time.time())
            labels = []
            values = []

            for sec in range(now - 29, now + 1):
                labels.append(time.strftime("%H:%M:%S", time.localtime(sec)))
                values.append(self.packet_timeline.get(sec, 0))

            top_sources = sorted(
                self.source_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            breakdown = {
                "Normal": self.normal_packets,
                "DDoS": self.attack_counts.get("DDoS", 0),
                "Port Scan": self.attack_counts.get("Port Scan", 0),
                "Brute Force": self.attack_counts.get("Brute Force", 0),
                "SQL Injection": self.attack_counts.get("SQL Injection", 0),
            }

            return {
                "total_packets": self.total_packets,
                "normal_packets": self.normal_packets,
                "total_attacks": self.total_attacks,
                "attack_breakdown": breakdown,
                "recent_attacks": list(self.recent_attacks),
                "top_sources": [
                    {"ip": ip, "count": count} for ip, count in top_sources
                ],
                "traffic": {
                    "labels": labels,
                    "values": values,
                },
                "capture_mode": "Live",
            }