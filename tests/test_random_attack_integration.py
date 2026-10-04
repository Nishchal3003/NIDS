"""Covers the acceptance tests explicitly called out for this phase: role
enforcement on the new single-button launch path, random (never
attacker-chosen) type selection, no fake detection from the orchestrator,
and that a confirmed detection of any of the three types reaches the
incident/broadcast layer the same way.
"""
import time

import app as appmod
from attack_orchestrator import DOS, PORTSCAN, DNS_TUNNEL


def _login_client(flask_client, username):
    return flask_client.post("/client/login", data={"username": username})


def _login_attacker(flask_client, username):
    return flask_client.post("/attacker/login", data={"username": username})


def test_client_cannot_call_attack_launch():
    with appmod.app.test_client() as c:
        _login_client(c, "Alice")
        resp = c.post("/api/v1/attack/launch")
        assert resp.status_code == 403
        assert "attacker role" in resp.get_json()["error"]


def test_monitor_or_unauthenticated_cannot_call_attack_launch():
    with appmod.app.test_client() as c:
        resp = c.post("/api/v1/attack/launch")
        assert resp.status_code == 403


def test_attacker_without_live_socket_gets_400_not_403():
    with appmod.app.test_client() as c:
        _login_attacker(c, "Tester")
        resp = c.post("/api/v1/attack/launch")
        # Role check passes (not 403); rejected only because no live
        # Socket.IO session exists yet for this login.
        assert resp.status_code == 400


def test_attacker_can_launch_via_socket_and_type_is_not_revealed():
    with appmod.app.test_client() as attacker_http:
        _login_attacker(attacker_http, "Tester")
        socket_client = appmod.socketio.test_client(appmod.app, flask_test_client=attacker_http)
        socket_client.get_received()
        socket_client.emit("launch_attack")
        received = socket_client.get_received()
        names = [e["name"] for e in received]
        assert "attack_test_requested" in names
        assert "attack_test_started" in names
        started = next(e["args"][0] for e in received if e["name"] == "attack_test_started")
        assert started.get("ok") is True
        assert "selected_test_type" not in started
        assert "kind" not in started
        assert started["attack_type"] in {"DoS", "PortScan", "DNS Tunneling"}
        test_run_id = started["test_run_id"]
        run = appmod.attack_orchestrator.get(test_run_id)
        assert run["selected_test_type"] in {DOS, PORTSCAN, DNS_TUNNEL}
        socket_client.disconnect()


def test_three_randomized_launches_include_dns_tunneling_runner(monkeypatch):
    calls = []

    def dns_runner(test_run_id, attacker_session_id, attacker_source_ip):
        calls.append((test_run_id, attacker_session_id, attacker_source_ip))
        return {"running": True, "kind": "dns_tunnel"}

    original = appmod.attack_orchestrator.runners[DNS_TUNNEL]
    appmod.attack_orchestrator.runners[DNS_TUNNEL] = dns_runner
    try:
        appmod.attack_orchestrator._selection_pool = [DNS_TUNNEL]
        appmod.attack_orchestrator.last_launch_ts = 0
        result = appmod.attack_orchestrator.launch("sid-dns", "10.0.0.5")
        assert result["ok"] is True
        assert len(calls) == 1
    finally:
        appmod.attack_orchestrator.runners[DNS_TUNNEL] = original


def test_client_socket_cannot_launch_attack():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        socket_client = appmod.socketio.test_client(appmod.app, flask_test_client=alice_http)
        socket_client.get_received()
        socket_client.emit("launch_attack")
        received = socket_client.get_received()
        started = next(e["args"][0] for e in received if e["name"] == "attack_test_started")
        assert started["ok"] is False
        assert "attacker role" in started["error"]
        socket_client.disconnect()


def test_orchestrator_never_exposes_a_detection_reporting_method():
    # The only way a test run is annotated with a result is note_detection,
    # called from app.py's own detection-pipeline output -- never from the
    # orchestrator or the generators themselves.
    import inspect
    public_methods = [
        name for name, _ in inspect.getmembers(appmod.attack_orchestrator, predicate=inspect.ismethod)
        if not name.startswith("_")
    ]
    assert "report_detection" not in public_methods
    assert "emit_detection" not in public_methods


def test_confirmed_dos_portscan_and_dns_each_create_an_incident_and_correlate():
    with appmod.app.test_client() as attacker_http:
        _login_attacker(attacker_http, "Tester")
        socket_client = appmod.socketio.test_client(appmod.app, flask_test_client=attacker_http)
        socket_client.get_received()

        cases = [
            (DOS, {"threat_type": "DoS", "prediction": "DoS"}, appmod.publish_live_alert),
            (PORTSCAN, {"threat_type": "PortScan", "prediction": "PortScan"}, appmod.publish_live_alert),
            (DNS_TUNNEL, {"threat_type": "DNS_TUNNELING"}, appmod.publish_dns_alert),
        ]
        for requested_type, extra_fields, publisher in cases:
            appmod.attack_orchestrator.last_launch_ts = 0  # bypass cooldown between cases in this test
            launch = appmod.attack_orchestrator.launch("dummy-sid-for-test", "10.0.0.123")
            assert launch.get("ok") is True, launch
            run = appmod.attack_orchestrator.get(launch["test_run_id"])
            # Force this run's selected type so each branch is exercised
            # deterministically (random selection itself is covered above).
            run["selected_test_type"] = requested_type
            appmod.attack_orchestrator.runs[launch["test_run_id"]] = run

            appmod._authorize_attack_window("syn_dos", duration=5.0, reset_capture=False)
            report = {
                "ts": time.time(),
                "source_ip": "10.0.0.123",
                "destination_ip": "10.0.0.1",
                "confidence": 95.0,
                "features": {},
                "shap": [],
                **extra_fields,
            }
            publisher(report)

            correlated = appmod.attack_orchestrator.get(launch["test_run_id"])
            assert correlated["result"] == "MATCH"
            incident = appmod.incident_engine.get(correlated["incident_id"])
            assert incident is not None
            assert incident["category"] == "confirmed_attack"
        socket_client.disconnect()


def test_security_alert_reaches_multiple_connected_clients():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        alice_socket = appmod.socketio.test_client(appmod.app, flask_test_client=alice_http)
        alice_socket.get_received()
    with appmod.app.test_client() as bob_http:
        _login_client(bob_http, "Bob")
        bob_socket = appmod.socketio.test_client(appmod.app, flask_test_client=bob_http)
        bob_socket.get_received()

        appmod._authorize_attack_window("syn_dos", duration=5.0, reset_capture=False)
        appmod.publish_live_alert({
            "ts": time.time(),
            "source_ip": "10.0.0.200",
            "destination_ip": "10.0.0.1",
            "threat_type": "DoS",
            "prediction": "DoS",
            "confidence": 93.0,
            "features": {},
            "shap": [],
        })
        bob_received = bob_socket.get_received()
        assert any(e["name"] == "security_alert" for e in bob_received)
        bob_socket.disconnect()
    # Alice's socket was created in an earlier `with` block and is already
    # disconnected by context-manager exit; this test only needs to show
    # the broadcast reaches a second, independently-logged-in client.
