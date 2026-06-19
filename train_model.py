import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder

FEATURE_NAMES = [
    "packet_size",
    "packets_per_sec",
    "unique_ports",
    "auth_attempts",
    "sql_score",
    "syn_ratio",
]

LABELS = ["Normal", "DDoS", "Port Scan", "Brute Force", "SQL Injection"]


def _ensure_dirs():
    os.makedirs("models", exist_ok=True)
    os.makedirs("logs", exist_ok=True)


def _make_block(label, n, rng):
    rows = []

    for _ in range(n):
        if label == "Normal":
            packet_size = int(rng.normal(500, 120))
            pps = float(max(1, rng.normal(8, 4)))
            unique_ports = int(max(1, rng.normal(2, 1)))
            auth_attempts = int(max(0, rng.normal(0, 1)))
            sql_score = int(max(0, rng.normal(0, 0.5)))
            syn_ratio = float(min(1.0, max(0.0, rng.normal(0.2, 0.1))))

        elif label == "DDoS":
            packet_size = int(rng.normal(420, 100))
            pps = float(max(50, rng.normal(220, 90)))
            unique_ports = int(max(1, rng.normal(2, 1)))
            auth_attempts = int(max(0, rng.normal(0, 1)))
            sql_score = int(max(0, rng.normal(0, 0.5)))
            syn_ratio = float(min(1.0, max(0.0, rng.normal(0.9, 0.08))))

        elif label == "Port Scan":
            packet_size = int(rng.normal(250, 70))
            pps = float(max(5, rng.normal(30, 10)))
            unique_ports = int(max(10, rng.normal(60, 18)))
            auth_attempts = int(max(0, rng.normal(0, 1)))
            sql_score = int(max(0, rng.normal(0, 0.5)))
            syn_ratio = float(min(1.0, max(0.0, rng.normal(0.7, 0.1))))

        elif label == "Brute Force":
            packet_size = int(rng.normal(220, 60))
            pps = float(max(5, rng.normal(25, 8)))
            unique_ports = int(max(1, rng.normal(1, 1)))
            auth_attempts = int(max(8, rng.normal(35, 15)))
            sql_score = int(max(0, rng.normal(0, 0.5)))
            syn_ratio = float(min(1.0, max(0.0, rng.normal(0.5, 0.15))))

        elif label == "SQL Injection":
            packet_size = int(rng.normal(700, 150))
            pps = float(max(1, rng.normal(10, 4)))
            unique_ports = int(max(1, rng.normal(2, 1)))
            auth_attempts = int(max(0, rng.normal(0, 1)))
            sql_score = int(max(2, rng.normal(12, 4)))
            syn_ratio = float(min(1.0, max(0.0, rng.normal(0.15, 0.08))))

        else:
            raise ValueError(f"Unknown label: {label}")

        rows.append(
            [
                max(40, packet_size),
                round(pps, 2),
                max(1, unique_ports),
                max(0, auth_attempts),
                max(0, sql_score),
                round(syn_ratio, 3),
                label,
            ]
        )

    return rows


def build_dataset(seed=42):
    rng = np.random.default_rng(seed)

    rows = []
    rows += _make_block("Normal", 1200, rng)
    rows += _make_block("DDoS", 700, rng)
    rows += _make_block("Port Scan", 700, rng)
    rows += _make_block("Brute Force", 700, rng)
    rows += _make_block("SQL Injection", 700, rng)

    df = pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def main():
    _ensure_dirs()

    df = build_dataset()

    X = df[FEATURE_NAMES].copy()
    y = df["label"].copy()

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    model = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight="balanced_subsample",
    )

    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    acc = accuracy_score(y_test, preds)
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, preds, target_names=le.classes_))

    payload = {
        "model": model,
        "label_encoder": le,
        "feature_names": FEATURE_NAMES,
    }

    joblib.dump(payload, "models/ids_model.pkl")

    meta = {
        "accuracy": float(acc),
        "features": FEATURE_NAMES,
        "labels": list(le.classes_),
    }

    with open("models/metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print("Model saved to models/ids_model.pkl")
    print("Metadata saved to models/metadata.json")


if __name__ == "__main__":
    main()