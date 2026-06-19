import threading
from flask import Flask, jsonify, render_template

from detector import IntrusionDetector
from packet_capture import PacketCaptureEngine
from store import IDSStore

app = Flask(__name__)

store = IDSStore()
detector = IntrusionDetector()
engine = PacketCaptureEngine(store=store, detector=detector, iface=None)

_started = False
_start_lock = threading.Lock()


def start_capture_once():
    global _started
    with _start_lock:
        if _started:
            return
        thread = threading.Thread(target=engine.start, daemon=True)
        thread.start()
        _started = True


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(store.snapshot())


@app.route("/api/health")
def api_health():
    return jsonify(
        {
            "status": "ok",
            "capture_started": _started,
        }
    )


if __name__ == "__main__":
    start_capture_once()

    import os
    port = int(os.environ.get("PORT", 5000))

    app.run(
        debug=False,
        host="0.0.0.0",
        port=port
    )