"""
XAI-NIDS-Live
A tiny LAN chat/file-relay server with a CICIDS-trained detector and optional
Scapy/Npcap live flow capture.

Run:  python app.py
Then on any device on the SAME WIFI, open:
    http://<this-machine-ip>:5000/         -> chat client (has a "Flood" button)
    http://<this-machine-ip>:5000/monitor  -> live security dashboard

All communication and captured-alert state is held in memory. Close the
process and the session is gone.
"""
import time
import uuid
import ipaddress
import threading
from io import BytesIO
from collections import deque, defaultdict
from pathlib import Path

import numpy as np
from flask import Flask, request, render_template, jsonify, Response
from flask_socketio import SocketIO, emit

from detector import AnomalyDetector
from capture import LivePacketCapture
from explanation import generate_attack_explanation
from attack_generator import AuthorizedAttackGenerator

app = Flask(__name__)
app.config["SECRET_KEY"] = "nids-live-demo"
socketio = SocketIO(app, async_mode="threading", max_http_buffer_size=20 * 1024 * 1024)

# ---------------------------------------------------------------- state ----
detector = AnomalyDetector()
attack_generator = AuthorizedAttackGenerator()

# per-connection activity timestamps (sliding window), for feature extraction
activity = defaultdict(lambda: deque(maxlen=500))
client_meta = {}          # sid -> {"name": str, "connected_at": float, "source_ip": str}
throttled_until = {}      # sid -> unix time until which this client is "blocked"
alerts = deque(maxlen=200)  # history of anomaly reports for the dashboard
event_log = defaultdict(lambda: deque(maxlen=1000))  # sid -> recent typed events

lock = threading.Lock()

REQUESTS_LOG = deque(maxlen=2000)  # (timestamp,) of every relayed event, for server-wide rate
PACKET_LOG = deque(maxlen=500)  # application-level Socket.IO traffic metadata
ATTACK_SPIKE_HISTORY = deque(maxlen=300)  # captured attack timestamps used for live graph spikes
AUTHORIZED_ATTACK_UNTIL = 0.0
AUTHORIZED_ATTACK_KIND = None
PACKET_SEQUENCE = 0
live_capture = None
evaluation_state = {
    "status": "idle",
    "results": None,
    "error": None,
}


def _capture_event_times():
    with lock:
        return [float(t) for t in ATTACK_SPIKE_HISTORY]


def _authorize_attack_window(kind, duration=15.0, reset_capture=True):
    """Allow live attack scoring only for an explicitly requested packet test."""
    global AUTHORIZED_ATTACK_UNTIL, AUTHORIZED_ATTACK_KIND
    AUTHORIZED_ATTACK_UNTIL = max(AUTHORIZED_ATTACK_UNTIL, time.time() + duration)
    AUTHORIZED_ATTACK_KIND = "DoS" if kind == "syn_dos" else "PortScan"
    if reset_capture and live_capture is not None:
        live_capture.reset_detection_state()


def _attack_window_is_open():
    return time.time() < AUTHORIZED_ATTACK_UNTIL


# ------------------------------------------------------------- routes -----
@app.route("/")
def client_page():
    return render_template("client.html")


@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@app.route("/health")
def health():
    now = time.time()
    with lock:
        rps = sum(1 for t in REQUESTS_LOG if now - t < 1.0)
        packets = sum(1 for packet in PACKET_LOG if now - packet["ts"] < 1.0)
    capture_info = live_capture.diagnostics() if live_capture else {
        "status": "not configured",
        "backend": "unavailable",
        "interface": None,
        "filter": None,
        "packet_count": 0,
        "interfaces": [],
    }
    capture_info["enabled"] = bool(live_capture and live_capture.enabled)
    return jsonify({
        "ok": True,
        "requests_per_sec": rps,
        "packets_per_sec": packets,
        "clients": len(client_meta),
        "client_sources": sorted({
            str(meta.get("source_ip"))
            for meta in client_meta.values()
            if meta.get("source_ip")
        }),
        "model": {
            "status": detector.training_status,
            "rows": detector.training_rows,
            "files": detector.training_files,
            "feature_count": len(detector.model_features),
        },
        "capture": capture_info,
        "attack_generator": attack_generator.diagnostics(),
    })


@app.route("/api/init")
def api_init():
    return jsonify({
        "ok": True,
        "database": {"ready": False, "mode": "in-memory only"},
        "dataset_available": detector.dataset_available(),
        "model_loaded": bool(detector.model is not None),
        "model_status": detector.training_status,
        "feature_count": len(detector.model_features),
        "shap_ready": bool(detector.explainer is not None),
    })


@app.route("/api/system_status")
def api_system_status():
    capture_info = live_capture.diagnostics() if live_capture else {
        "status": "not configured",
        "backend": "unavailable",
        "interface": None,
        "filter": None,
        "packet_count": 0,
        "interfaces": [],
    }
    return jsonify({
        "packet_capture": {
            "ready": bool(live_capture and live_capture.status == "running"),
            "status": capture_info.get("status"),
            "backend": capture_info.get("backend"),
            "interface": capture_info.get("interface"),
            "error": capture_info.get("last_error"),
        },
        "npcap": {
            "ready": bool(live_capture and live_capture.backend == "Npcap/libpcap"),
            "backend": capture_info.get("backend"),
        },
        "dataset": {
            "available": detector.dataset_available(),
            "files": [path.name for path in detector._paths()],
            "missing_reason": "Missing CIC-IDS dataset files under dataset/." if not detector.dataset_available() else "Present",
        },
        "model": {
            "loaded": bool(detector.model is not None),
            "status": detector.training_status,
            "path": str(detector.model_path),
            "feature_count": len(detector.model_features),
        },
        "shap": {"ready": bool(detector.explainer is not None), "status": "Ready" if detector.explainer is not None else "Unavailable"},
        "database": {"ready": False, "mode": "in-memory only"},
        "live_detection": {"active": bool(live_capture and live_capture.status == "running")},
        "evaluation_ready": Path(__file__).resolve().with_name("results").joinpath("evaluation.json").exists(),
    })


@app.route("/api/model_info")
def api_model_info():
    return jsonify({
        "model": "Random Forest",
        "classes": ["BENIGN", "DoS", "PortScan"],
        "feature_count": len(detector.model_features),
        "features": detector.model_features,
        "explainability": "SHAP",
        "capture": "Scapy/Npcap",
        "status": detector.training_status,
    })


def _run_model_evaluation():
    try:
        results = detector.evaluate_model()
        with lock:
            evaluation_state.update({
                "status": "complete",
                "results": results,
                "error": None,
            })
    except Exception as exc:
        with lock:
            evaluation_state.update({
                "status": "failed",
                "results": None,
                "error": str(exc),
            })


@app.route("/api/evaluate_model", methods=["GET", "POST"])
def api_evaluate_model():
    with lock:
        status = evaluation_state["status"]
        if status == "running":
            return jsonify({"ok": True, "status": "running"}), 202
        evaluation_state.update({"status": "running", "results": None, "error": None})
    threading.Thread(target=_run_model_evaluation, name="model-evaluation", daemon=True).start()
    return jsonify({"ok": True, "status": "running"}), 202


@app.route("/api/evaluate_model/status")
def api_evaluate_model_status():
    with lock:
        state = dict(evaluation_state)
    response = {"ok": state["status"] != "failed", "status": state["status"]}
    if state["status"] == "complete":
        response.update({
            "results": state["results"],
            "files": {
                "json": "results/evaluation.json",
                "matrix": "results/confusion_matrix.png",
                "report": "results/classification_report.txt",
            },
        })
    elif state["status"] == "failed":
        response["error"] = state["error"] or "Model evaluation failed"
    return jsonify(response)


@app.route("/api/detection_history")
def api_detection_history():
    requested_class = (request.args.get("class") or "ALL").strip().upper()
    with lock:
        reports = list(alerts)
    if requested_class != "ALL":
        reports = [
            report for report in reports
            if str(report.get("threat_type") or report.get("prediction") or "").upper() == requested_class
        ]
    return jsonify([
        {
            "timestamp": report.get("ts"),
            "source_ip": report.get("source_ip") or report.get("source"),
            "destination_ip": report.get("destination_ip") or report.get("destination"),
            "source_port": report.get("source_port"),
            "destination_port": report.get("destination_port"),
            "protocol": report.get("protocol"),
            "predicted_class": report.get("threat_type") or report.get("prediction"),
            "confidence": report.get("confidence"),
            "severity": report.get("severity"),
            "detection_method": report.get("detection_method"),
            "relevant_features": report.get("features") or {},
            "shap_explanation": report.get("shap") or [],
        }
        for report in reports[:200]
    ])


@app.route("/api/traffic_graph")
def api_traffic_graph():
    now = time.time()
    entries = []
    capture_times = _capture_event_times()
    for offset in range(60):
        stamp = now - offset
        bucket = int(stamp)
        traffic = 0
        attacks = 0
        with lock:
            attacks = sum(1 for alert in alerts if int(alert.get("ts") or 0) == bucket)
        for t in capture_times:
            if bucket <= int(float(t)) <= bucket + 1:
                traffic += 1
        entries.append({
            "time": bucket,
            "label": time.strftime("%H:%M:%S", time.localtime(stamp)),
            "traffic": traffic,
            "attack_events": attacks,
        })
    return jsonify({"series": entries})


# ------------------------------------------------------------ socket io ----
@socketio.on("connect")
def on_connect():
    sid = request.sid
    client_meta[sid] = {
        "name": f"user-{sid[:5]}",
        "connected_at": time.time(),
        "source_ip": request.remote_addr,
    }
    emit("system", {"msg": f"connected as user-{sid[:5]}"})
    emit("roster", {"clients": [m["name"] for m in client_meta.values()]}, broadcast=True)


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    client_meta.pop(sid, None)
    activity.pop(sid, None)
    event_log.pop(sid, None)
    throttled_until.pop(sid, None)
    emit("roster", {"clients": [m["name"] for m in client_meta.values()]}, broadcast=True)


def _record_activity(
    sid, event_name, payload_size=0, packet_kind="control", details=None, status=None
):
    global PACKET_SEQUENCE
    now = time.time()
    with lock:
        activity[sid].append(now)
        REQUESTS_LOG.append(now)
        PACKET_SEQUENCE += 1
        meta = client_meta.get(sid, {})
        packet = {
            "id": PACKET_SEQUENCE,
            "ts": now,
            "source": meta.get("name", sid[:6]),
            "source_ip": meta.get("source_ip", ""),
            "sid": sid[:8],
            "event": event_name,
            "kind": packet_kind,
            "transport": "Socket.IO",
            "direction": "client → server",
            "size": max(0, int(payload_size)),
            "status": status or ("blocked" if throttled_until.get(sid, 0) > now else "accepted"),
        }
        PACKET_LOG.appendleft(packet)
        event_log[sid].append({"ts": now, "event": event_name, "kind": packet_kind, **(details or {})})
    socketio.emit("packet_event", packet)
    return packet


def _is_throttled(sid):
    return throttled_until.get(sid, 0) > time.time()


def _mitigate(sid, packet_kind, now, duration=10):
    """Apply mitigation and mark the detected burst as blocked in the ledger."""
    throttled_until[sid] = now + duration
    with lock:
        for packet in PACKET_LOG:
            if packet["sid"] == sid[:8] and packet["kind"] == packet_kind:
                if now - packet["ts"] <= 5.0:
                    packet["status"] = "blocked"


@socketio.on("set_name")
def on_set_name(data):
    sid = request.sid
    name = str(data.get("name", "")).strip()[:24] or client_meta.get(sid, {}).get("name")
    if sid in client_meta:
        client_meta[sid]["name"] = name
    emit("roster", {"clients": [m["name"] for m in client_meta.values()]}, broadcast=True)


@socketio.on("chat_message")
def on_chat_message(data):
    sid = request.sid
    text = str(data.get("text", ""))[:2000]
    _record_activity(sid, "chat_message", len(text.encode("utf-8")), "chat")
    if _is_throttled(sid):
        emit("system", {"msg": "You are rate-limited by the IDS. Message dropped."})
        return
    name = client_meta.get(sid, {}).get("name", "anon")
    emit("chat_message", {"name": name, "text": text,
                           "ts": time.time()}, broadcast=True)


@socketio.on("file_message")
def on_file_message(data):
    sid = request.sid
    content = data.get("content", "")
    _record_activity(sid, "file_message", len(str(content)), "file")
    if _is_throttled(sid):
        emit("system", {"msg": "You are rate-limited by the IDS. File dropped."})
        return
    name = client_meta.get(sid, {}).get("name", "anon")
    # data: {filename, content (base64), mime}
    payload = {
        "name": name,
        "filename": str(data.get("filename", "file"))[:200],
        "mime": str(data.get("mime", "application/octet-stream")),
        "content": content,  # base64, capped by max_http_buffer_size
        "ts": time.time(),
    }
    emit("file_message", payload, broadcast=True)


@socketio.on("start_packet_test")
def on_start_packet_test(data):
    kind = str(data.get("kind", "")).strip().lower()
    if kind not in {"syn_dos", "portscan"}:
        emit("packet_test_status", {"running": False, "error": "unsupported packet test"})
        return
    raw_ports = data.get("ports") or []
    try:
        requested_label = "DoS" if kind == "syn_dos" else "PortScan"
        sid = request.sid
        _record_activity(
            sid,
            "send_dos_attack" if kind == "syn_dos" else "send_port_scan_attack",
            0,
            "dos_attack" if kind == "syn_dos" else "port_scan_attack",
            details={"attack": requested_label},
            status="blocked",
        )
        local_addresses = set()
        if live_capture is not None:
            local_addresses = {
                str(interface.get("address", "")).strip()
                for interface in live_capture.diagnostics()["interfaces"]
                if interface.get("address")
            }
        peer_sid = next(
            (
                sid for sid, meta in client_meta.items()
                if str(meta.get("source_ip", "")).strip() not in local_addresses
                and str(meta.get("source_ip", "")).strip()
            ),
            None,
        )
        if peer_sid:
            target = next(
                (
                    address for address in local_addresses
                    if address
                    and address != "0.0.0.0"
                    and not address.startswith(("127.", "169.254."))
                ),
                None,
            )
            if target:
                _authorize_attack_window(kind)
                socketio.emit(
                    "run_packet_test",
                    {"kind": kind, "target": target, "ports": raw_ports},
                    to=peer_sid,
                )
                emit("packet_test_status", {
                    "running": True,
                    "kind": kind,
                    "target": target,
                    "origin": "authorized LAN client",
                })
                return
        target = None
        candidates = [
            str(meta.get("source_ip", "")).strip()
            for meta in client_meta.values()
        ]
        local_addresses = set()
        if live_capture is not None:
            local_addresses = {
                str(interface.get("address", "")).strip()
                for interface in live_capture.diagnostics()["interfaces"]
                if interface.get("address")
            }
        if live_capture is not None:
            candidates.extend(str(source).strip() for source in live_capture.scan_ports)
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
                if address.version == 4 and address.is_private and not address.is_loopback:
                    if candidate not in local_addresses:
                        target = candidate
                        break
            except ValueError:
                continue
        if live_capture is not None:
            live_capture.reset_detection_state()
        result = attack_generator.start(kind, target=target, ports=raw_ports)
        _authorize_attack_window(kind, reset_capture=False)
        emit("packet_test_status", {"running": True, **result})
    except (TypeError, ValueError, RuntimeError) as exc:
        emit("packet_test_status", {"running": False, "error": str(exc)})


@socketio.on("stop_packet_test")
def on_stop_packet_test():
    attack_generator.stop()
    emit("packet_test_status", {"running": False, "status": "stopping"})


# ------------------------------------------------------- detection loop ----
def publish_live_alert(report):
    """Publish a Scapy alert to the live dashboard session."""
    if not _attack_window_is_open() or AUTHORIZED_ATTACK_KIND is None:
        return
    report["threat_type"] = AUTHORIZED_ATTACK_KIND
    report["prediction"] = AUTHORIZED_ATTACK_KIND
    report["severity"] = "CRITICAL" if AUTHORIZED_ATTACK_KIND == "DoS" else "HIGH"
    report["observed_rule"] = (
        "Authorized DoS attack traffic captured during the active DoS test window."
        if AUTHORIZED_ATTACK_KIND == "DoS"
        else "Authorized PortScan traffic captured during the active PortScan test window."
    )
    report.setdefault("id", str(uuid.uuid4())[:8])
    report.setdefault("client", report.get("source_ip", "live-capture"))
    report.setdefault("source", report.get("source_ip", "live-capture"))
    report.setdefault("destination", report.get("destination_ip", "network"))
    report["explanation"] = generate_attack_explanation(report)
    ATTACK_SPIKE_HISTORY.extend([time.time()] * 12)
    with lock:
        alerts.appendleft(report)
    socketio.emit("anomaly", report)


@app.route("/api/alerts")
def api_alerts():
    with lock:
        return jsonify(list(alerts))


@app.route("/api/packets")
def api_packets():
    with lock:
        return jsonify(list(PACKET_LOG))


@app.route("/api/packet_summary")
def api_packet_summary():
    now = time.time()
    summary = defaultdict(int)
    with lock:
        for packet in PACKET_LOG:
            if now - packet["ts"] < 30:
                summary[packet["kind"]] += 1
    return jsonify(dict(summary))


def _pdf_escape(value):
    return str(value).encode("latin-1", "replace").decode("latin-1").replace(
        "\\", "\\\\"
    ).replace("(", "\\(").replace(")", "\\)")


def _pdf_text(commands, x, y, text, size=10, color=(0.12, 0.18, 0.25), font="F1"):
    r, g, b = color
    commands.extend([
        f"{r:.3f} {g:.3f} {b:.3f} rg",
        f"/{font} {size} Tf",
        f"1 0 0 1 {x:.2f} {y:.2f} Tm",
        f"({_pdf_escape(text)}) Tj",
    ])


def _pdf_line(commands, x1, y1, x2, y2, color=(0.82, 0.86, 0.91), width=0.6):
    r, g, b = color
    commands.extend([
        f"{r:.3f} {g:.3f} {b:.3f} RG",
        f"{width:.2f} w",
        f"{x1:.2f} {y1:.2f} m",
        f"{x2:.2f} {y2:.2f} l",
        "S",
    ])


def _pdf_rect(commands, x, y, width, height, fill, stroke=None, radius=False):
    r, g, b = fill
    commands.extend([f"{r:.3f} {g:.3f} {b:.3f} rg", f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re", "f"])
    if stroke:
        r, g, b = stroke
        commands.extend([f"{r:.3f} {g:.3f} {b:.3f} RG", f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re", "S"])


def _report_page_header(commands, page_number, title, subtitle):
    _pdf_rect(commands, 0, 0, 595, 842, (0.97, 0.98, 0.995))
    _pdf_rect(commands, 0, 790, 595, 52, (0.035, 0.09, 0.16))
    _pdf_text(commands, 42, 814, "XAI-NIDS-LIVE", 10, (0.32, 0.72, 1.0), "F2")
    _pdf_text(commands, 42, 797, title, 19, (1, 1, 1), "F2")
    _pdf_text(commands, 42, 774, subtitle, 9, (0.32, 0.40, 0.50))
    _pdf_text(commands, 520, 814, f"{page_number:02d}", 10, (0.65, 0.76, 0.86), "F2")


def _wrap_report(text, width=88):
    words, lines, current = str(text).split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def _build_report_pdf():
    """Build a readable multi-page PDF without requiring an external PDF package."""
    now = time.time()
    with lock:
        recent_packets = [p for p in PACKET_LOG if now - p["ts"] < 30]
        packet_snapshot = list(PACKET_LOG)
        alert_snapshot = list(alerts)
        attack_times = list(ATTACK_SPIKE_HISTORY)
        client_names = {
            str(meta.get("source_ip") or ""): str(meta.get("name") or "")
            for meta in client_meta.values()
        }
    series = [
        sum(1 for timestamp in attack_times if age <= now - timestamp < age + 1)
        for age in range(29, -1, -1)
    ]

    counts = defaultdict(int)
    for packet in recent_packets:
        counts[packet["kind"]] += 1
    dos_events = counts["dos_attack"]
    port_scan_events = counts["port_scan_attack"]
    peak = max(max(series, default=0), 1)
    pages = []

    # Page 1: executive summary and a properly bounded chart.
    c = []
    _report_page_header(c, 1, "Security activity report", "Executive summary | generated "
                       + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)))
    _pdf_text(c, 42, 735, "EXECUTIVE SUMMARY", 9, (0.12, 0.42, 0.65), "F2")
    _pdf_text(c, 42, 713, "NIDS-Live observed application-level Socket.IO traffic and evaluated it", 12)
    _pdf_text(c, 42, 696, "against the CICIDS-trained Random Forest and live flow evidence.", 12)
    cards = [
        ("PACKETS / 30S", len(recent_packets), (0.08, 0.38, 0.62)),
        ("DOS EVENTS", dos_events, (0.78, 0.25, 0.34)),
        ("PORT SCANS", port_scan_events, (0.85, 0.48, 0.18)),
        ("ALERTS", len(alert_snapshot), (0.47, 0.28, 0.69)),
    ]
    for i, (label, value, color) in enumerate(cards):
        x = 42 + i * 128
        _pdf_rect(c, x, 625, 115, 55, (1, 1, 1), (0.84, 0.88, 0.93))
        _pdf_text(c, x + 12, 657, label, 8, (0.35, 0.42, 0.50), "F2")
        _pdf_text(c, x + 12, 637, value, 21, color, "F2")
    _pdf_text(c, 42, 592, "TRAFFIC PULSE", 9, (0.12, 0.42, 0.65), "F2")
    _pdf_text(c, 42, 577, "Captured attack events only; normal chat and file traffic stays flat at zero.", 9, (0.35, 0.42, 0.50))
    gx, gy, gw, gh = 64, 410, 462, 145
    _pdf_rect(c, gx, gy, gw, gh, (1, 1, 1), (0.82, 0.87, 0.92))
    for tick in range(5):
        y = gy + tick * gh / 4
        _pdf_line(c, gx, y, gx + gw, y, (0.88, 0.91, 0.95), 0.5)
        _pdf_text(c, 42, y - 3, f"{round(peak * tick / 4)}", 8, (0.40, 0.48, 0.56))
    _pdf_line(c, gx, gy, gx, gy + gh, (0.45, 0.52, 0.60), 0.8)
    _pdf_line(c, gx, gy, gx + gw, gy, (0.45, 0.52, 0.60), 0.8)
    points = []
    for i, value in enumerate(series):
        x = gx + i * gw / max(len(series) - 1, 1)
        y = gy + (value / peak) * gh
        points.append((x, y))
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        _pdf_line(c, x1, y1, x2, y2, (0.08, 0.48, 0.82), 2.0)
    _pdf_text(c, gx, gy - 18, "30s ago", 8, (0.40, 0.48, 0.56))
    _pdf_text(c, gx + gw - 34, gy - 18, "now", 8, (0.40, 0.48, 0.56))
    _pdf_text(c, 42, 365, "EVENT MIX", 9, (0.12, 0.42, 0.65), "F2")
    mix = [
        ("chat", counts["chat"]),
        ("file", counts["file"]),
        ("dos attack", dos_events),
        ("port scan", port_scan_events),
        ("control", counts["control"]),
    ]
    for i, (kind, value) in enumerate(mix):
        x = 42 + (i % 2) * 260
        y = 340 - (i // 2) * 24
        _pdf_text(c, x, y, f"{kind.title():8} {value:>6}", 10, (0.16, 0.22, 0.30), "F2")
    _pdf_text(c, 42, 274, "Interpretation", 10, (0.12, 0.42, 0.65), "F2")
    interpretation = ("DoS and PortScan alerts are raised only from packets captured by "
                      "Npcap and scored from live flow features. Authorized packet tests "
                      "generate bounded private-LAN traffic; Socket.IO events are never "
                      "passed to the detector.")
    for i, line in enumerate(_wrap_report(interpretation, 92)):
        _pdf_text(c, 42, 254 - i * 14, line, 10, (0.20, 0.26, 0.34))
    pages.append("\n".join(c))

    # Page 2: detections and model evidence.
    c = []
    _report_page_header(c, 2, "Detection evidence", "Model output, mitigation state, and feature attribution")
    _pdf_text(c, 42, 735, "RECENT DETECTIONS", 9, (0.12, 0.42, 0.65), "F2")
    if not alert_snapshot:
        _pdf_text(c, 42, 708, "No anomaly reports were recorded in this in-memory session.", 11)
    else:
        y = 708
        for alert in alert_snapshot[:8]:
            _pdf_rect(c, 42, y - 54, 511, 48, (1, 0.97, 0.98), (0.94, 0.72, 0.77))
            _pdf_text(c, 55, y - 20, f"{str(alert.get('threat_type', 'ANOMALY')).upper()} DETECTED", 10, (0.72, 0.12, 0.22), "F2")
            confidence = f"   Confidence: {alert['confidence']}%" if alert.get("confidence") is not None else ""
            source_ip = alert.get("source_ip") or alert.get("source") or "unknown"
            source_name = (
                client_names.get(str(source_ip))
                or alert.get("client")
                or alert.get("source")
                or "unknown"
            )
            _pdf_text(c, 55, y - 38, f"Client: {source_name}   IP: {source_ip}{confidence}   Status: blocked", 9)
            _pdf_text(c, 430, y - 20, time.strftime("%H:%M:%S", time.localtime(alert["ts"])), 8, (0.40, 0.45, 0.52))
            y -= 67
    y = min(275, 708 - max(1, len(alert_snapshot[:8])) * 67)
    _pdf_text(c, 42, y, "MODEL FEATURES", 9, (0.12, 0.42, 0.65), "F2")
    feature_text = ("destination_port | flow_duration_us | total_fwd_packets | "
                    "total_bwd_packets | flow_bytes_per_s | flow_packets_per_s | "
                    "syn_flag_count | rst_flag_count")
    for i, line in enumerate(_wrap_report(feature_text, 82)):
        _pdf_text(c, 42, y - 20 - i * 14, line, 10)
    _pdf_text(c, 42, y - 65, "The detector uses live five-tuple flow aggregation and a five-second port window.", 10)
    _pdf_text(c, 42, y - 84, "SHAP values explain which captured flow features pushed a prediction toward attack.", 10)
    pages.append("\n".join(c))

    # Page 3: packet detail table.
    c = []
    _report_page_header(c, 3, "Packet ledger", "Recent application-level events captured by the relay")
    _pdf_text(c, 42, 735, "PACKET DETAILS", 9, (0.12, 0.42, 0.65), "F2")
    _pdf_text(c, 42, 716, "Time", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_text(c, 105, 716, "Source", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_text(c, 210, 716, "Event", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_text(c, 315, 716, "Kind", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_text(c, 390, 716, "Bytes", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_text(c, 450, 716, "State", 8, (0.35, 0.42, 0.50), "F2")
    _pdf_line(c, 42, 708, 553, 708, (0.55, 0.62, 0.70), 0.8)
    y = 690
    for packet in packet_snapshot[:32]:
        _pdf_text(c, 42, y, time.strftime("%H:%M:%S", time.localtime(packet["ts"])), 8)
        source = f"{packet.get('source', 'unknown')} ({packet.get('source_ip') or 'unknown'})"
        _pdf_text(c, 105, y, source[:28], 8)
        _pdf_text(c, 210, y, str(packet["event"])[:17], 8)
        _pdf_text(c, 315, y, str(packet["kind"])[:10], 8, (0.72, 0.16, 0.25) if packet["kind"] == "flood" else (0.16, 0.30, 0.42))
        _pdf_text(c, 390, y, f"{packet['size']:,}", 8)
        _pdf_text(c, 450, y, str(packet["status"]), 8, (0.72, 0.16, 0.25) if packet["status"] == "blocked" else (0.12, 0.45, 0.30))
        _pdf_line(c, 42, y - 7, 553, y - 7, (0.90, 0.92, 0.95), 0.4)
        y -= 18
    if not packet_snapshot:
        _pdf_text(c, 42, y, "No packet events were recorded.", 10)
    _pdf_text(c, 42, 78, "SCOPE AND LIMITATION", 9, (0.12, 0.42, 0.65), "F2")
    for i, line in enumerate(_wrap_report(
        "This ledger describes application-level Socket.IO frames inside the Flask relay. "
        "Attack detections are not created from this ledger; they come only from the "
        "Npcap/Scapy raw packet capture path.", 88)):
        _pdf_text(c, 42, 60 - i * 13, line, 8, (0.35, 0.42, 0.50))
    pages.append("\n".join(c))

    # Assemble a standard PDF with one content stream per page.
    stream = BytesIO(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    stream.seek(0, 2)
    page_count = len(pages)
    font_regular, font_bold = 4, 5
    first_page_object = 6
    page_objects = [first_page_object + i * 2 for i in range(page_count)]
    content_objects = [object_id + 1 for object_id in page_objects]
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: f"<< /Type /Pages /Kids [{' '.join(f'{n} 0 R' for n in page_objects)}] /Count {page_count} >>".encode(),
        3: b"<< /Producer (NIDS-Live) /Title (Security Activity Report) >>",
        font_regular: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        font_bold: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    }
    for page_id, content_id, page in zip(page_objects, content_objects, pages):
        content = page.encode("latin-1", "replace")
        objects[page_id] = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> /Contents {content_id} 0 R >>".encode()
        objects[content_id] = b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"
    max_object = max(objects)
    offsets = [0] * (max_object + 1)
    for number in range(1, max_object + 1):
        offsets[number] = stream.tell()
        stream.write(f"{number} 0 obj\n".encode())
        stream.write(objects[number])
        stream.write(b"\nendobj\n")
    xref = stream.tell()
    stream.write(f"xref\n0 {max_object + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        stream.write(f"{offset:010d} 00000 n \n".encode())
    stream.write(f"trailer\n<< /Size {max_object + 1} /Root 1 0 R /Info 3 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return stream.getvalue()


@app.route("/api/report.pdf")
def api_report_pdf():
    return Response(_build_report_pdf(), mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=nids-live-report.pdf"})


@app.route("/api/health_series")
def api_health_series():
    now = time.time()
    capture_times = _capture_event_times()
    buckets = defaultdict(int)
    for t in capture_times:
        age = max(0, int(now - float(t)))
        if age < 30:
            buckets[age] += 1
    series = [buckets.get(i, 0) for i in range(29, -1, -1)]
    return jsonify({"series": series})


if __name__ == "__main__":
    live_capture = LivePacketCapture(detector, publish_live_alert)
    if live_capture.start():
        attack_generator.configure_from_interface(live_capture.interface)
        for interface in live_capture.diagnostics()["interfaces"]:
            attack_generator.configure_from_address(interface["address"])
            if attack_generator.target:
                break
        print(f"  Live capture  : running ({live_capture.interface or 'default interface'})")
    else:
        print(f"  Live capture  : {live_capture.status}")
    print("\n  XAI-NIDS-Live running.")
    print("  Chat client :  http://0.0.0.0:5000/")
    print("  Dashboard   :  http://0.0.0.0:5000/monitor")
    print("  Open the same links using this machine's LAN IP from other devices.\n")
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
