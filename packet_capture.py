import time
import random
from collections import defaultdict, deque

AUTH_PORTS = {22, 23, 445, 3389}
SQL_PATTERNS = ["' OR 1=1", "UNION SELECT", "DROP TABLE", "--", "admin'--"]


class PacketCaptureEngine:
    def __init__(self, store, detector, iface=None):
        self.store = store
        self.detector = detector
        self.history = defaultdict(lambda: deque(maxlen=200))

    def start(self):
        print("[*] DEMO MODE — Railway cloud simulated traffic")
        normal_sources = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        ddos_src = "10.10.10.50"
        scan_src = "10.10.10.60"
        brute_src = "10.10.10.70"
        sql_src = "10.10.10.80"

        while True:
            self._burst_normal(random.choice(normal_sources))
            self._burst_ddos(ddos_src)
            self._burst_port_scan(scan_src)
            self._burst_bruteforce(brute_src)
            self._burst_sql(sql_src)
            time.sleep(2)

    def _burst_normal(self, src_ip):
        for _ in range(random.randint(5, 10)):
            self._finalize(src_ip, "8.8.8.8", random.choice([53, 80, 443]),
                            random.randint(300, 900), "GET /index.html", 0)
            time.sleep(0.05)

    def _burst_ddos(self, src_ip):
        for _ in range(random.randint(15, 25)):
            self._finalize(src_ip, "172.217.16.78", 80,
                            random.randint(100, 300), "SYN", 1)
            time.sleep(0.01)

    def _burst_port_scan(self, src_ip):
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
        random.shuffle(ports)
        for port in ports:
            self._finalize(src_ip, "192.168.1.1", port,
                            random.randint(60, 150), "SYN probe", 1)
            time.sleep(0.03)

    def _burst_bruteforce(self, src_ip):
        for _ in range(random.randint(10, 18)):
            self._finalize(src_ip, "192.168.1.20",
                            random.choice([22, 23, 3389, 445]),
                            random.randint(100, 220), "LOGIN failed", 1)
            time.sleep(0.02)

    def _burst_sql(self, src_ip):
        payloads = ["' OR 1=1 --", "UNION SELECT username, password FROM users", "DROP TABLE users; --"]
        for p in payloads:
            self._finalize(src_ip, "192.168.1.30", 80,
                            random.randint(400, 1000), p, 0)
            time.sleep(0.06)

    def _sql_score(self, payload):
        if not payload:
            return 0
        text = payload.lower()
        return sum(1 for pat in SQL_PATTERNS if pat.lower() in text)

    def _finalize(self, src_ip, dst_ip, port, size, payload, syn):
        now = time.time()
        event = {
            "timestamp": now, "src_ip": src_ip, "dst_ip": dst_ip,
            "dst_port": port, "packet_size": size, "syn_flag": syn,
            "sql_score": self._sql_score(payload),
        }
        self.history[src_ip].append(event)

        recent_5 = [x for x in self.history[src_ip] if now - x["timestamp"] <= 5]
        recent_10 = [x for x in self.history[src_ip] if now - x["timestamp"] <= 10]
        recent_30 = [x for x in self.history[src_ip] if now - x["timestamp"] <= 30]

        features = [
            float(size),
            len(recent_5) / 5.0,
            float(len(set(x["dst_port"] for x in recent_10))),
            float(len([x for x in recent_30 if x["dst_port"] in AUTH_PORTS])),
            float(event["sql_score"]),
            float(len([x for x in recent_10 if x["syn_flag"] == 1]) / max(1, len(recent_10))),
        ]

        prediction = self.detector.predict(features)
        event["label"] = prediction["label"]
        event["confidence"] = prediction["confidence"]
        event["severity"] = "Critical" if prediction["label"] in ("DDoS", "SQL Injection") else \
                             "High" if prediction["label"] in ("Port Scan", "Brute Force") else "Low"

        self.store.add_event(event)