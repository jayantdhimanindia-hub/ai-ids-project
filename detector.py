import os
import warnings
import numpy as np
import joblib

warnings.filterwarnings("ignore")

FEATURE_NAMES = [
    "packet_size",
    "packets_per_sec",
    "unique_ports",
    "auth_attempts",
    "sql_score",
    "syn_ratio",
]


class IntrusionDetector:
    def __init__(self, model_path="models/ids_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.label_encoder = None
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            payload = joblib.load(self.model_path)
            self.model = payload["model"]
            self.label_encoder = payload["label_encoder"]
            self.feature_names = payload.get("feature_names", FEATURE_NAMES)
            print("[✓] Model loaded successfully")
        else:
            print("[!] Model file not found — using rule-based fallback")

    def predict(self, features):
        arr = np.array(features, dtype=float).reshape(1, -1)

        if self.model is not None and self.label_encoder is not None:
            # ML Model se predict
            df_input = __import__('pandas').DataFrame(arr, columns=self.feature_names)
            pred_class = int(self.model.predict(df_input)[0])
            proba = self.model.predict_proba(df_input)[0]
            confidence = float(np.max(proba))
            label = str(self.label_encoder.inverse_transform([pred_class])[0])
        else:
            # Fallback — rule based
            packet_size, pps, unique_ports, auth_attempts, sql_score, syn_ratio = arr[0]
            if pps >= 150 and syn_ratio >= 0.75:
                label = "DDoS"
                confidence = 0.92
            elif unique_ports >= 20:
                label = "Port Scan"
                confidence = 0.90
            elif auth_attempts >= 25:
                label = "Brute Force"
                confidence = 0.89
            elif sql_score >= 2:
                label = "SQL Injection"
                confidence = 0.91
            else:
                label = "Normal"
                confidence = 0.88

        return {
            "label": label,
            "confidence": round(confidence * 100, 2),
            "is_attack": label != "Normal",
        }