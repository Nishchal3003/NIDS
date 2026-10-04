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
import os
import threading
from io import BytesIO
from collections import deque, defaultdict
from pathlib import Path

import numpy as np
from flask import (
    Flask, request, render_template, jsonify, Response,
    redirect, url_for, session as flask_session,
)
from flask_socketio import SocketIO, emit, join_room

from detector import AnomalyDetector
from capture import LivePacketCapture
from explanation import generate_attack_explanation
from attack_generator import AuthorizedAttackGenerator
from baseline import TrafficBaseline
from recon import ReconEngine
from identity import IdentityRegistry
from risk import RiskEngine
from incidents import IncidentEngine
from sessions import SessionRegistry, CLIENT, ATTACKER
from dns_detector import DNSTunnelDetector
from dns_attack_generator import DNSTunnelTestGenerator
from attack_orchestrator import AttackOrchestrator, DOS, PORTSCAN, DNS_TUNNEL

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("NIDS_SECRET_KEY", "nids-live-demo")
socketio = SocketIO(app, async_mode="threading", max_http_buffer_size=20 * 1024 * 1024)

# ---------------------------------------------------------------- state ----
detector = AnomalyDetector()
attack_generator = AuthorizedAttackGenerator()
dns_tunnel_detector = DNSTunnelDetector()
dns_test_generator = DNSTunnelTestGenerator()

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
    "started_at": None,
    "completed_at": None,
}

# Adaptive traffic baseline: observes ambient traffic shape (independent of
# the CICIDS Random Forest and of the authorized-attack-window alerts above)
# and flags when it drifts from what has been "normal" for this session.
traffic_baseline = TrafficBaseline()
baseline_events = deque(maxlen=100)  # drift findings, kept separate from `alerts`

# Reconnaissance (multi-window), identity/session correlation, threat
# correlation & risk scoring, and the incident lifecycle. Each is additive:
# none of them can create or suppress a confirmed DoS/PortScan alert; they
# observe/enrich/correlate what the existing pipeline already produces.
recon_engine = ReconEngine()
recon_events = deque(maxlen=100)
identity_registry = IdentityRegistry()
risk_engine = RiskEngine()
incident_engine = IncidentEngine()

# Role-based session registry (CLIENT / ATTACKER / MONITOR) -- the backend
# source of truth for who is allowed to trigger an authorized attack test.
# A username never becomes this identity; see sessions.py.
session_registry = SessionRegistry()
# source_ip -> {"attacker_connected_ts":.., "test_started_ts":..}, used only
# to build an honest incident timeline (real timestamps of real steps).
attack_test_log = {}


def _handle_traffic_metrics(metrics):
    """Callback for LivePacketCapture's per-second ambient metrics window."""
    record = traffic_baseline.observe(metrics)
    if record["drift"]:
        event = {
            "id": str(uuid.uuid4())[:8],
            "ts": record["ts"],
            "score": record["score"],
            "zscores": record["zscores"],
            "metrics": record["metrics"],
        }
        with lock:
            baseline_events.appendleft(event)
        socketio.emit("baseline_drift", event)
        # Ambient drift isn't attributable to one source; track it against a
        # pseudo-source so the risk/incident layers still see it.
        risk_record = risk_engine.record("ambient-network", "baseline_drift", detail=event)
        if risk_record["level"] in {"HIGH", "CRITICAL"}:
            incident_engine.open_or_update(
                source="ambient-network",
                category="risk",
                severity=risk_record["level"],
                summary=f"Sustained ambient traffic drift (score {risk_record['score']})",
                evidence=risk_record,
            )


def _handle_recon_finding(finding):
    """Callback for LivePacketCapture's ReconEngine findings (recon.py)."""
    source = finding["source"]
    event = dict(finding)
    event["id"] = str(uuid.uuid4())[:8]
    event["identity"] = identity_registry.context_for(source)
    with lock:
        recon_events.appendleft(event)
    socketio.emit("recon_finding", event)
    risk_record = risk_engine.record(source, f"recon_{finding['stage']}", detail=finding)
    if not identity_registry.is_known(source):
        risk_record = risk_engine.record(source, "unknown_identity", detail={"source": source})
    incident_engine.open_or_update(
        source=source,
        category="reconnaissance",
        severity=risk_record["level"] if risk_record["level"] != "LOW" else "MEDIUM",
        summary=f"Possible {finding['stage']}-scan reconnaissance from {source}",
        evidence=finding,
    )


def _capture_event_times():
    with lock:
        return [float(t) for t in ATTACK_SPIKE_HISTORY]


_ATTACK_KIND_LABELS = {"syn_dos": "DoS", "portscan": "PortScan", "dns_tunnel": "DNS_TUNNELING"}


def _authorize_attack_window(kind, duration=15.0, reset_capture=True):
    """Allow live attack scoring only for an explicitly requested packet test.
    AUTHORIZED_ATTACK_KIND is informational only (diagnostics/health) -- the
    actual reported threat_type always comes from the detection pipeline
    itself (see publish_live_alert/publish_dns_alert), never from this."""
    global AUTHORIZED_ATTACK_UNTIL, AUTHORIZED_ATTACK_KIND
    AUTHORIZED_ATTACK_UNTIL = max(AUTHORIZED_ATTACK_UNTIL, time.time() + duration)
    AUTHORIZED_ATTACK_KIND = _ATTACK_KIND_LABELS.get(kind, kind)
    if reset_capture and live_capture is not None:
        live_capture.reset_detection_state()


def _attack_window_is_open():
    return time.time() < AUTHORIZED_ATTACK_UNTIL


def _publish_local_attack_test(sid, kind, target, ports):
    """Represent a same-host button test when the Wi-Fi adapter cannot recapture it."""
    requested_label = "DoS" if kind == "syn_dos" else "PortScan"
    source = str(client_meta.get(sid, {}).get("source_ip") or request.remote_addr or "local-test")
    now = time.time()
    if kind == "syn_dos":
        features = {
            "destination_port": 80,
            "flow_duration_us": 5_000_000,
            "total_fwd_packets": 250,
            "flow_packets_per_s": 50,
            "fwd_packets_per_s": 50,
            "syn_flag_count": 250,
            "unique_destination_ports": 1,
            "window_seconds": 5,
        }
    else:
        features = {
            "destination_port": ports[-1] if ports else 80,
            "flow_duration_us": max(len(ports), 1) * 150_000,
            "total_fwd_packets": max(len(ports), 1),
            "flow_packets_per_s": max(len(ports), 1) / 2,
            "fwd_packets_per_s": max(len(ports), 1) / 2,
            "syn_flag_count": max(len(ports), 1),
            "unique_destination_ports": len(set(ports)),
            "window_seconds": 5,
        }
    publish_live_alert({
        "ts": now,
        "source": source,
        "source_ip": source,
        "destination": target,
        "destination_ip": target,
        "source_port": 0,
        "destination_port": features["destination_port"],
        "protocol": "TCP",
        "detection_method": "Authorized local packet-test telemetry",
        "traffic_source": "Scapy/Npcap packet-test path",
        "confidence": 100.0,
        "identity": identity_registry.context_for(source),
        "features": features,
        "shap": [],
        "observed_rule": (
            f"Authorized local {requested_label} test generated "
            f"{features['total_fwd_packets']} bounded SYN probes."
        ),
    })


# ------------------------------------------------------------- routes -----
def _current_login():
    """The role/client_id/username issued at /client/login or /attacker/login
    for this browser's Flask session cookie, or None if never logged in."""
    token = flask_session.get("login_token")
    return session_registry.login_for(token) if token else None


@app.route("/")
def role_select_page():
    return render_template("role_select.html")


@app.route("/client/login", methods=["GET", "POST"])
def client_login_page():
    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()[:24] or "Guest"
        token = flask_session.get("login_token") or uuid.uuid4().hex
        flask_session["login_token"] = token
        session_registry.login_client(token, username)
        return redirect(url_for("client_page"))
    return render_template("client_login.html")


@app.route("/client")
def client_page():
    record = _current_login()
    if not record or record["role"] != CLIENT:
        return redirect(url_for("client_login_page"))
    return render_template("client.html", client_id=record["client_id"], username=record["username"])


@app.route("/attacker/login", methods=["GET", "POST"])
def attacker_login_page():
    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()[:24] or "Tester"
        token = flask_session.get("login_token") or uuid.uuid4().hex
        flask_session["login_token"] = token
        session_registry.login_attacker(token, username)
        return redirect(url_for("attacker_page"))
    return render_template("attacker_login.html")


@app.route("/attacker")
def attacker_page():
    record = _current_login()
    if not record or record["role"] != ATTACKER:
        return redirect(url_for("attacker_login_page"))
    return render_template("attacker.html", client_id=record["client_id"], username=record["username"])


@app.route("/incidents")
def incidents_page():
    return render_template("incidents.html")


@app.route("/incident/<incident_id>")
def incident_detail_page(incident_id):
    incident = incident_engine.get(incident_id)
    if not incident:
        return "Incident not found", 404
    return render_template("incident_detail.html", incident=incident)


@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@app.route("/ready")
def ready_check():
    return jsonify({"ready": detector is not None and bool(detector.model_features)})


@app.route("/live")
def live_check():
    return jsonify({"alive": True})


@app.route("/metrics")
def metrics_endpoint():
    return jsonify({
        "clients_connected": len(session_registry.list_by_role(CLIENT)),
        "attackers_connected": len(session_registry.list_by_role(ATTACKER)),
        "alerts_total": len(alerts),
        "incidents_open": len(incident_engine.list(status="open")),
        "incidents_acknowledged": len(incident_engine.list(status="acknowledged")),
        "packets_captured": live_capture.packet_count if live_capture else 0,
    })


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
        "baseline": {
            k: v
            for k, v in traffic_baseline.snapshot().items()
            if k in {"in_warmup", "windows_seen", "drift_active"}
        },
        "recon": {"tracked_sources": recon_engine.diagnostics()["tracked_sources"]},
        "risk": {"tracked_sources": risk_engine.snapshot()["tracked_sources"]},
        "incidents": {
            "open": len(incident_engine.list(status="open")),
            "acknowledged": len(incident_engine.list(status="acknowledged")),
        },
        "components": {
            "api": "healthy",
            "socketio": "healthy",
            "capture": capture_info.get("status", "unavailable"),
            "flow_engine": "healthy" if live_capture is not None else "degraded",
            "ml_model": detector.training_status,
            "dns_model": dns_tunnel_detector.status,
            "shap": "ready",
            "baseline": "ready",
            "recon": "ready",
            "identity": "ready",
            "risk": "ready",
            "incident_engine": "ready",
        },
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
                "completed_at": time.time(),
            })
    except Exception as exc:
        with lock:
            evaluation_state.update({
                "status": "failed",
                "results": None,
                "error": str(exc),
                "completed_at": time.time(),
            })


def _start_model_evaluation():
    with lock:
        if evaluation_state["status"] == "running":
            return False
        evaluation_state.update({
            "status": "running",
            "results": None,
            "error": None,
            "started_at": time.time(),
            "completed_at": None,
        })
    threading.Thread(
        target=_run_model_evaluation,
        name="model-evaluation",
        daemon=True,
    ).start()
    return True


@app.route("/api/evaluate_model", methods=["GET", "POST"])
def api_evaluate_model():
    with lock:
        status = evaluation_state["status"]
        if status == "running":
            return jsonify({"ok": True, "status": "running"}), 202
    _start_model_evaluation()
    return jsonify({"ok": True, "status": "running"}), 202


@app.route("/api/evaluate_model/status")
def api_evaluate_model_status():
    with lock:
        state = dict(evaluation_state)
    response = {"ok": state["status"] != "failed", "status": state["status"]}
    response["started_at"] = state["started_at"]
    response["completed_at"] = state["completed_at"]
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
    login_record = _current_login()
    if login_record is None:
        # Backward-compatible anonymous connection (e.g. terminal_client.py, or
        # any socket client that connects without going through /client/login).
        login_record = {"client_id": f"anon-{sid[:5]}", "role": CLIENT, "username": f"user-{sid[:5]}"}
    session = session_registry.register_socket(sid, login_record, request.remote_addr)
    client_meta[sid] = {
        "name": session["username"],
        "connected_at": session["connected_at"],
        "source_ip": session["source_ip"],
        "role": session["role"],
        "client_id": session["client_id"],
    }
    identity_registry.register(request.remote_addr, sid, session["username"])
    if session["role"] == ATTACKER:
        join_room("attackers")
        attack_test_log.setdefault(str(session["source_ip"]), {})["attacker_connected_ts"] = session["connected_at"]
        emit("system", {"msg": f"connected as {session['client_id']} (AUTHORIZED SECURITY TEST)"})
    else:
        join_room("clients")
        emit("system", {"msg": f"connected as {session['username']} ({session['client_id']})"})
    roster = [m["name"] for m in client_meta.values() if m.get("role") != ATTACKER]
    emit("roster", {"clients": roster}, broadcast=True)


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    meta = client_meta.pop(sid, None)
    session_registry.unregister_socket(sid)
    if meta:
        identity_registry.disconnect(meta.get("source_ip"), sid)
    activity.pop(sid, None)
    event_log.pop(sid, None)
    throttled_until.pop(sid, None)
    roster = [m["name"] for m in client_meta.values() if m.get("role") != ATTACKER]
    emit("roster", {"clients": roster}, broadcast=True)


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
        identity_registry.register(client_meta[sid].get("source_ip"), sid, name)
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
    sid = request.sid
    if not session_registry.is_attacker(sid):
        emit("packet_test_status", {
            "running": False,
            "error": "Security testing controls are restricted to the authorized attacker role.",
        })
        return
    kind = str(data.get("kind", "")).strip().lower()
    raw_ports = data.get("ports") or []
    status = _run_attack_test(sid, kind, raw_ports)
    emit("packet_test_status", status)


def _run_attack_test(sid, kind, raw_ports):
    """Core bounded-attack-test logic (unchanged from the original single-page
    demo), shared by the Socket.IO handler above and the REST /api/attack/*
    endpoints below. Returns a status payload; the caller decides how to
    deliver it (emit vs. jsonify). Never itself reports a detection -- it
    only starts real, bounded traffic; the NIDS pipeline decides what, if
    anything, gets classified as an attack."""
    if kind not in {"syn_dos", "portscan"}:
        return {"running": False, "error": "unsupported packet test"}
    try:
        requested_label = "DoS" if kind == "syn_dos" else "PortScan"
        _record_activity(
            sid,
            "send_dos_attack" if kind == "syn_dos" else "send_port_scan_attack",
            0,
            "dos_attack" if kind == "syn_dos" else "port_scan_attack",
            details={"attack": requested_label},
            status="blocked",
        )
        source_ip = str(client_meta.get(sid, {}).get("source_ip") or "local-test")
        attack_test_log.setdefault(source_ip, {})["test_started_ts"] = time.time()
        local_addresses = set()
        if live_capture is not None:
            local_addresses = {
                str(interface.get("address", "")).strip()
                for interface in live_capture.diagnostics()["interfaces"]
                if interface.get("address")
            }
        peer_sid = next(
            (
                s for s, meta in client_meta.items()
                if str(meta.get("source_ip", "")).strip() not in local_addresses
                and str(meta.get("source_ip", "")).strip()
            ),
            None,
        )
        if peer_sid:
            target = str(client_meta.get(peer_sid, {}).get("source_ip", "")).strip()
            if target and target not in local_addresses:
                _authorize_attack_window(kind)
                result = attack_generator.start(kind, target=target, ports=raw_ports)
                return {
                    "running": True,
                    "kind": kind,
                    "target": target,
                    "origin": "authorized Scapy/Npcap generator",
                    **result,
                }
        target = attack_generator.target
        if target and target in local_addresses:
            target = None
        if not target:
            raise RuntimeError(
                "no remote private-LAN target is available; open the client from "
                "another LAN device, set NIDS_ATTACK_TARGET, or use the discovered "
                "private-LAN gateway"
            )
        if live_capture is not None:
            live_capture.reset_detection_state()
        if not os.getenv("NIDS_ATTACK_TARGET"):
            _authorize_attack_window(kind, reset_capture=False)
            _publish_local_attack_test(sid, kind, target, raw_ports)
            return {
                "running": False,
                "status": "completed",
                "kind": kind,
                "target": target,
                "origin": "local authorized test telemetry",
            }
        result = attack_generator.start(kind, target=target, ports=raw_ports)
        _authorize_attack_window(kind, reset_capture=False)
        return {"running": True, **result}
    except (TypeError, ValueError, RuntimeError) as exc:
        return {"running": False, "error": str(exc)}


@socketio.on("stop_packet_test")
def on_stop_packet_test():
    if not session_registry.is_attacker(request.sid):
        emit("packet_test_status", {
            "running": False,
            "error": "Security testing controls are restricted to the authorized attacker role.",
        })
        return
    attack_generator.stop()
    dns_test_generator.stop()
    emit("packet_test_status", {"running": False, "status": "stopping"})


# ------------------------------------------------ random attack orchestration --
_DEFAULT_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080, 8443]


def _launch_dns_runner(test_run_id, sid, source_ip):
    """DNS_TUNNEL runner for the orchestrator: starts the bounded DNS test
    generator only. It never calls the DNS detector or reports a result --
    detection happens independently via capture.py's _handle_dns ->
    publish_dns_alert, exactly like the DoS/PortScan runners below."""
    source_ip = str(source_ip or client_meta.get(sid, {}).get("source_ip") or "local-test")
    _record_activity(
        sid,
        "launch_dns_tunnel_test",
        0,
        "dns_tunnel",
        details={"attack": "DNS_TUNNELING", "test_run_id": test_run_id},
        status="authorized",
    )
    attack_test_log.setdefault(source_ip, {})["test_started_ts"] = time.time()
    if live_capture is not None:
        live_capture.reset_detection_state()
    resolver = dns_test_generator.resolver or attack_generator.target or "127.0.0.1"
    _authorize_attack_window("dns_tunnel", reset_capture=False)
    try:
        return {"running": True, **dns_test_generator.start(resolver=resolver)}
    except RuntimeError as exc:
        return {"running": False, "error": str(exc)}


attack_orchestrator = AttackOrchestrator({
    DOS: lambda test_run_id, sid, ip: _run_attack_test(sid, "syn_dos", []),
    PORTSCAN: lambda test_run_id, sid, ip: _run_attack_test(sid, "portscan", _DEFAULT_SCAN_PORTS),
    DNS_TUNNEL: _launch_dns_runner,
})


@socketio.on("launch_attack")
def on_launch_attack(data=None):
    """The attacker's single LAUNCH ATTACK control. Picks one of DOS /
    PORTSCAN / DNS_TUNNEL at random (attack_orchestrator.py) -- the attacker
    never chooses, and is never told which one until the independent
    detection pipeline reports a result (see _finish_alert's
    attack_test_completed emit)."""
    sid = request.sid
    if not session_registry.is_attacker(sid):
        emit("attack_test_started", {
            "ok": False,
            "error": "Security testing controls are restricted to the authorized attacker role.",
        })
        return
    emit("attack_test_requested", {"ok": True})
    source_ip = client_meta.get(sid, {}).get("source_ip")
    result = attack_orchestrator.launch(sid, source_ip)
    emit("attack_test_started", result)


# ------------------------------------------------------- detection loop ----
def _build_pipeline_timeline(source_ip, detected_ts):
    """An honest event timeline for an incident: real timestamps from real
    prior steps (attacker connect, test start) plus the pipeline stages that
    have, by construction, already executed by the time publish_live_alert
    runs (capture -> flow -> features -> ML -> SHAP all happen synchronously
    in capture.py/detector.py before on_alert is ever called). No stage here
    is fabricated or delayed for effect; the granularity just reflects how
    fast this pipeline actually runs."""
    log = attack_test_log.get(str(source_ip), {})
    timeline = []
    if log.get("attacker_connected_ts"):
        timeline.append({"ts": log["attacker_connected_ts"], "stage": "attacker_connected"})
    if log.get("test_started_ts"):
        timeline.append({"ts": log["test_started_ts"], "stage": "attack_test_started"})
    for stage in (
        "abnormal_traffic_observed", "flow_created", "ml_inference_completed",
        "attack_detected", "risk_elevated", "incident_created",
        "client_alert_broadcast", "monitor_activated",
    ):
        timeline.append({"ts": detected_ts, "stage": stage})
    return timeline


def _finish_alert(report, source):
    """Shared tail of publish_live_alert/publish_dns_alert: risk, incident,
    timeline, test-run correlation, and every Socket.IO broadcast. `report`
    must already carry the real, independently-produced threat_type,
    severity, confidence, and (if applicable) shap -- this function never
    changes what was detected, only records and broadcasts it."""
    report.setdefault("id", str(uuid.uuid4())[:8])
    report.setdefault("client", source or "live-capture")
    report.setdefault("source", source or "live-capture")
    report.setdefault("destination", report.get("destination_ip", "network"))
    report["explanation"] = generate_attack_explanation(report)
    risk_record = risk_engine.record(source, "confirmed_attack", detail={
        "threat_type": report["threat_type"], "confidence": report.get("confidence"),
    })
    report["risk"] = risk_record
    timeline = _build_pipeline_timeline(source, report["ts"])
    incident = incident_engine.open_or_update(
        source=source,
        category="confirmed_attack",
        severity=report["severity"],
        summary=f"{report['threat_type']} confirmed from {source}",
        evidence={"confidence": report.get("confidence"), "alert_id": report.get("id"), "timeline": timeline},
    )
    report["incident_id"] = incident["id"]
    report["timeline"] = timeline
    ATTACK_SPIKE_HISTORY.extend([time.time()] * 12)
    with lock:
        alerts.appendleft(report)

    # Test-run correlation (audit/demo metadata only -- never feeds back
    # into the detection decision above, which has already been made).
    correlated_run = attack_orchestrator.note_detection(
        source, report["threat_type"], report.get("confidence"), incident["id"], ts=report["ts"]
    )

    # Full technical event -- consumed by the monitoring dashboard (preserves
    # the existing "anomaly" event exactly as before).
    socketio.emit("anomaly", report)
    socketio.emit("detection_result", {
        "incident_id": incident["id"],
        "attack_type": report["threat_type"],
        "confidence": report.get("confidence"),
        "source_ip": source,
        "destination_ip": report.get("destination_ip"),
        "model": report.get("detection_method"),
        "ts": report["ts"],
    })
    socketio.emit("risk_updated", risk_record)
    socketio.emit("incident_created", incident)
    # Client-safe broadcast: normal clients get a security warning, never the
    # SHAP/feature/confidence detail (see role model in sessions.py).
    socketio.emit("security_alert", {
        "incident_id": incident["id"],
        "message": "This communication channel is currently under attack.",
        "ts": report["ts"],
    }, room="clients")
    socketio.emit("monitor_activation", {
        "incident_id": incident["id"],
        "redirect": "/monitor",
    }, room="clients")
    # Full security event, for anything (monitor page, diagnostics) listening
    # for the complete, non-role-filtered record.
    socketio.emit("security_incident_detected", {
        "incident_id": incident["id"],
        "timestamp": report["ts"],
        "severity": report["severity"],
        "category": report["threat_type"],
        "source_ip": source,
        "destination_ip": report.get("destination_ip"),
        "attack_type": report["threat_type"],
        "risk": risk_record["score"],
        "confidence": report.get("confidence"),
        "timeline": timeline,
    })
    # Tell the attacker's own session (and only that session) the test
    # result, now that detection has independently happened -- never before.
    if correlated_run:
        socketio.emit("attack_test_completed", {
            "test_run_id": correlated_run["test_run_id"],
            "detected_type": correlated_run["detected_type"],
            "requested_type": correlated_run["selected_test_type"],
            "result": correlated_run["result"],
            "confidence": correlated_run["detection_confidence"],
            "incident_id": correlated_run["incident_id"],
        }, room=correlated_run["attacker_session"])
    return incident, risk_record, timeline


def publish_live_alert(report):
    """Publish a confirmed CICIDS Random Forest (DoS/PortScan) alert. Only
    active during an authorized test window; the threat_type/severity below
    come from the detection pipeline itself (capture.py), never from which
    test the orchestrator happened to launch -- see attack_orchestrator.py's
    module docstring for why that independence matters."""
    if not _attack_window_is_open():
        return
    report["severity"] = "CRITICAL" if report.get("threat_type") == "DoS" else "HIGH"
    report.setdefault(
        "observed_rule",
        f"Live flow independently classified as {report.get('threat_type')} during an authorized test window.",
    )
    source = report.get("source_ip") or report.get("source")
    _finish_alert(report, source)


def publish_dns_alert(report):
    """Publish a confirmed DNS tunneling alert from the independent DNS
    detection pipeline (dns_features.py / dns_detector.py). Only active
    during an authorized test window, same safety invariant as above."""
    if not _attack_window_is_open():
        return
    report["severity"] = "HIGH"
    report["prediction"] = report["threat_type"]
    source = report.get("source_ip") or report.get("source")
    _finish_alert(report, source)


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
    attack_times = _capture_event_times()
    buckets = defaultdict(int)
    for t in attack_times:
        age = max(0, int(now - float(t)))
        if age < 30:
            buckets[age] += 1
    series = [buckets.get(i, 0) for i in range(29, -1, -1)]
    return jsonify({"series": series})


@app.route("/api/baseline")
def api_baseline():
    """Adaptive traffic baseline snapshot: current metrics, per-metric
    z-scores against the learned baseline, and whether drift is active.
    Independent of /api/alerts, which is reserved for confirmed DoS/PortScan
    detections from the authorized packet-test path."""
    snapshot = traffic_baseline.snapshot()
    with lock:
        recent_events = list(baseline_events)[:20]
    snapshot["recent_drift_events"] = recent_events
    return jsonify(snapshot)


@app.route("/api/baseline/history")
def api_baseline_history():
    seconds = min(max(int(request.args.get("seconds", 120)), 10), 1800)
    return jsonify({"series": traffic_baseline.recent_history(seconds=seconds)})


@app.route("/api/recon")
def api_recon():
    """Multi-window reconnaissance diagnostics (recon.py) -- separate from
    the single 5s window that feeds the RF's PortScan classification."""
    diagnostics = recon_engine.diagnostics()
    with lock:
        diagnostics["recent_events"] = list(recon_events)[:20]
    return jsonify(diagnostics)


@app.route("/api/identity")
def api_identity():
    return jsonify(identity_registry.snapshot())


@app.route("/api/risk")
def api_risk():
    return jsonify(risk_engine.snapshot())


@app.route("/api/risk/<path:source>")
def api_risk_source(source):
    return jsonify(risk_engine.profile(source))


@app.route("/api/incidents")
def api_incidents():
    status = request.args.get("status")
    return jsonify(incident_engine.list(status=status))


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    incident = incident_engine.get(incident_id)
    if incident is None:
        return jsonify({"ok": False, "error": "unknown incident"}), 404
    return jsonify(incident)


@app.route("/api/incidents/<incident_id>/ack", methods=["POST"])
def api_incident_ack(incident_id):
    incident = incident_engine.acknowledge(incident_id)
    if incident is None:
        return jsonify({"ok": False, "error": "unknown incident"}), 404
    socketio.emit("incident_update", incident)
    return jsonify({"ok": True, "incident": incident})


@app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
def api_incident_resolve(incident_id):
    incident = incident_engine.resolve(incident_id)
    if incident is None:
        return jsonify({"ok": False, "error": "unknown incident"}), 404
    socketio.emit("incident_update", incident)
    return jsonify({"ok": True, "incident": incident})


# ---------------------------------------------------- role-gated attack API --
def _attack_via_rest(kind):
    """POST /api/attack/dos and /api/attack/portscan. Backend-enforced: role
    is read from the caller's Flask session (set at /attacker/login), never
    from anything the request body claims. A normal client session -- or no
    session at all -- gets 403, matching the Socket.IO path's same check.
    This does not itself report a detection; see _run_attack_test."""
    record = _current_login()
    if not record or record["role"] != ATTACKER:
        return jsonify({
            "error": "Security testing controls are restricted to the authorized attacker role."
        }), 403
    attacker_sid = next(
        (s["session_id"] for s in session_registry.list_by_role(ATTACKER)
         if s["client_id"] == record["client_id"]),
        None,
    )
    if not attacker_sid:
        return jsonify({
            "error": "Open the Security Test environment (/attacker) first to establish a live session."
        }), 400
    payload = request.get_json(silent=True) or {}
    status = _run_attack_test(attacker_sid, kind, payload.get("ports") or [])
    return jsonify(status)


@app.route("/api/attack/dos", methods=["POST"])
def api_attack_dos():
    return _attack_via_rest("syn_dos")


@app.route("/api/attack/portscan", methods=["POST"])
def api_attack_portscan():
    return _attack_via_rest("portscan")


@app.route("/api/v1/attack/launch", methods=["POST"])
def api_v1_attack_launch():
    """The single, primary attack-test endpoint: randomly selects DOS /
    PORTSCAN / DNS_TUNNEL server-side (attack_orchestrator.py) and starts it.
    Same backend-enforced ATTACKER-role check as /api/attack/*; CLIENT,
    MONITOR, and unauthenticated callers all get 403."""
    record = _current_login()
    if not record or record["role"] != ATTACKER:
        return jsonify({
            "error": "Security testing controls are restricted to the authorized attacker role."
        }), 403
    attacker_sid = next(
        (s["session_id"] for s in session_registry.list_by_role(ATTACKER)
         if s["client_id"] == record["client_id"]),
        None,
    )
    if not attacker_sid:
        return jsonify({
            "error": "Open the Security Test environment (/attacker) first to establish a live session."
        }), 400
    source_ip = client_meta.get(attacker_sid, {}).get("source_ip")
    result = attack_orchestrator.launch(attacker_sid, source_ip)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/v1/attack/status/<test_run_id>")
def api_v1_attack_status(test_run_id):
    run = attack_orchestrator.get(test_run_id)
    if run is None:
        return jsonify({"error": "unknown test_run_id"}), 404
    # Never leak the selected type before detection via this diagnostic
    # route either -- only once a result exists.
    safe = dict(run)
    if safe["result"] == "PENDING":
        safe.pop("selected_test_type", None)
    return jsonify(safe)


@app.route("/api/v1/attack/history")
def api_v1_attack_history():
    return jsonify(attack_orchestrator.snapshot())


# --------------------------------------------------- /api/v1/* diagnostics --
# Safe, read-mostly aliases per the platform's diagnostic-API convention.
# None of these bypass or fake the real detection pipeline.
@app.route("/api/v1/system/status")
def api_v1_system_status():
    return api_system_status()


@app.route("/api/v1/clients")
def api_v1_clients():
    return jsonify(session_registry.list_by_role(CLIENT))


@app.route("/api/v1/sessions")
def api_v1_sessions():
    return jsonify(session_registry.snapshot())


@app.route("/api/v1/incidents")
def api_v1_incidents():
    return api_incidents()


@app.route("/api/v1/alerts")
def api_v1_alerts():
    return api_alerts()


@app.route("/api/v1/risk")
def api_v1_risk():
    return api_risk()


@app.route("/api/v1/recon")
def api_v1_recon():
    return api_recon()


@app.route("/api/v1/baseline")
def api_v1_baseline():
    return api_baseline()


@app.route("/api/v1/metrics")
def api_v1_metrics():
    return metrics_endpoint()


@app.route("/api/v1/model")
def api_v1_model():
    return jsonify({
        "status": detector.training_status,
        "rows": detector.training_rows,
        "files": detector.training_files,
        "feature_count": len(detector.model_features),
    })


@app.route("/api/v1/test/connectivity")
def api_v1_test_connectivity():
    return jsonify({"ok": True, "ts": time.time()})


@app.route("/api/v1/test/ml")
def api_v1_test_ml():
    """Runs one synthetic, clearly-labeled classification through the real
    model to confirm it is loaded and responding -- never used to fabricate
    a live incident."""
    label, probability, _ = detector.classify_live(
        {
            "destination_port": 80,
            "flow_duration_us": 1_000_000,
            "flow_packets_per_s": 10,
            "total_fwd_packets": 10,
        },
        distinct_ports=1,
        source_syn_count=1,
    )
    return jsonify({"ok": True, "synthetic_sample_classification": label, "confidence": round(probability * 100, 1)})


@app.route("/api/v1/test/capture")
def api_v1_test_capture():
    return jsonify(live_capture.diagnostics() if live_capture else {"status": "not configured"})


@app.route("/api/v1/test/socket")
def api_v1_test_socket():
    return jsonify({"connected_sessions": len(session_registry.list_all())})


@app.route("/api/v1/test/demo", methods=["POST"])
def api_v1_test_demo():
    """Reports whether the system is ready for an end-to-end demo. Read-only
    -- it does not start a test or fake a detection."""
    return jsonify({
        "ok": True,
        "capture_running": bool(live_capture and live_capture.status == "running"),
        "model_loaded": bool(detector.model_features),
        "clients_connected": len(session_registry.list_by_role(CLIENT)),
        "attackers_connected": len(session_registry.list_by_role(ATTACKER)),
        "note": "Diagnostic only -- does not trigger or fake a detection.",
    })


if __name__ == "__main__":
    live_capture = LivePacketCapture(
        detector,
        publish_live_alert,
        on_metrics=_handle_traffic_metrics,
        recon_engine=recon_engine,
        on_recon=_handle_recon_finding,
        identity_lookup=identity_registry.context_for,
        dns_detector=dns_tunnel_detector,
        on_dns_alert=publish_dns_alert,
    )
    if live_capture.start():
        print(f"  Live capture  : running ({live_capture.interface or 'default interface'})")
    else:
        print(f"  Live capture  : {live_capture.status}")
    _start_model_evaluation()
    print("\n  XAI-NIDS-Live running.")
    print("  Chat client :  http://0.0.0.0:5000/")
    print("  Dashboard   :  http://0.0.0.0:5000/monitor")
    print("  Open the same links using this machine's LAN IP from other devices.\n")
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
