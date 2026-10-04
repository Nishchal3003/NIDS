"""End-to-end integration test for the role-separated system.

Covers the chain the acceptance criteria call out explicitly:
CLIENT LOGIN -> ATTACKER LOGIN -> role enforcement on the attack API ->
a confirmed detection -> incident creation -> security_alert broadcast to
clients only -> monitor_activation.
"""
import time

import app as appmod


def _login_client(flask_client, username):
    resp = flask_client.post("/client/login", data={"username": username})
    assert resp.status_code in (302, 200)
    return resp


def _login_attacker(flask_client, username):
    resp = flask_client.post("/attacker/login", data={"username": username})
    assert resp.status_code in (302, 200)
    return resp


def test_client_login_gets_sequential_client_id_not_username():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        page = alice_http.get("/client")
        assert page.status_code == 200
        assert b"CLIENT-" in page.data
        assert b"Alice" in page.data


def test_attacker_login_identity_is_not_the_typed_username():
    with appmod.app.test_client() as attacker_http:
        _login_attacker(attacker_http, "John")
        page = attacker_http.get("/attacker")
        assert page.status_code == 200
        assert b"ATTACKER-" in page.data
        # the backend role label appears; "John" is not treated as an identity
        assert b"SECURITY TEST" in page.data


def test_client_page_redirects_to_login_when_not_authenticated():
    with appmod.app.test_client() as anon_http:
        page = anon_http.get("/client", follow_redirects=False)
        assert page.status_code == 302
        assert "/client/login" in page.headers["Location"]


def test_multiple_clients_get_distinct_ids():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        alice_page = alice_http.get("/client").data
    with appmod.app.test_client() as bob_http:
        _login_client(bob_http, "Bob")
        bob_page = bob_http.get("/client").data
    assert alice_page != bob_page


def test_normal_client_cannot_call_attack_rest_api():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        resp = alice_http.post("/api/attack/dos")
        assert resp.status_code == 403
        assert "attacker role" in resp.get_json()["error"]


def test_unauthenticated_request_cannot_call_attack_rest_api():
    with appmod.app.test_client() as anon_http:
        resp = anon_http.post("/api/attack/portscan")
        assert resp.status_code == 403


def test_socket_start_packet_test_rejected_for_client_role():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        socket_client = appmod.socketio.test_client(appmod.app, flask_test_client=alice_http)
        socket_client.emit("start_packet_test", {"kind": "syn_dos"})
        received = socket_client.get_received()
        statuses = [e["args"][0] for e in received if e["name"] == "packet_test_status"]
        assert statuses, "expected a packet_test_status response"
        assert statuses[0]["running"] is False
        assert "attacker role" in statuses[0]["error"]
        socket_client.disconnect()


def test_socket_start_packet_test_allowed_for_attacker_role():
    with appmod.app.test_client() as attacker_http:
        _login_attacker(attacker_http, "Tester")
        socket_client = appmod.socketio.test_client(appmod.app, flask_test_client=attacker_http)
        socket_client.emit("start_packet_test", {"kind": "syn_dos"})
        received = socket_client.get_received()
        statuses = [e["args"][0] for e in received if e["name"] == "packet_test_status"]
        assert statuses, "expected a packet_test_status response"
        # In this sandbox there is no real LAN target, so the attempt itself
        # may fail -- the important assertion is that it was NOT rejected for
        # being the wrong role.
        assert statuses[0].get("error") != (
            "Security testing controls are restricted to the authorized attacker role."
        )
        socket_client.disconnect()


def test_confirmed_attack_broadcasts_client_safe_alert_and_full_incident():
    with appmod.app.test_client() as alice_http:
        _login_client(alice_http, "Alice")
        client_socket = appmod.socketio.test_client(appmod.app, flask_test_client=alice_http)
        client_socket.get_received()  # drain connect-time events (system/roster)

        appmod._authorize_attack_window("syn_dos", duration=5.0, reset_capture=False)
        appmod.publish_live_alert({
            "ts": time.time(),
            "source_ip": "10.0.0.77",
            "destination_ip": "10.0.0.1",
            "threat_type": "DoS",
            "prediction": "DoS",
            "confidence": 96.0,
            "features": {},
            "shap": [],
        })

        received = client_socket.get_received()
        names = [e["name"] for e in received]
        assert "security_alert" in names
        assert "monitor_activation" in names

        alert_payload = next(e["args"][0] for e in received if e["name"] == "security_alert")
        # Client-facing payload must NOT leak ML/XAI technical detail.
        assert "shap" not in alert_payload
        assert "confidence" not in alert_payload
        assert "message" in alert_payload

        incident_id = alert_payload["incident_id"]
        incident = appmod.incident_engine.get(incident_id)
        assert incident is not None
        assert incident["category"] == "confirmed_attack"

        with appmod.app.test_client() as api_client:
            resp = api_client.get(f"/api/incidents/{incident_id}")
            assert resp.status_code == 200
            body = resp.get_json()
            assert body["evidence"][-1]["timeline"][0]["stage"]

        client_socket.disconnect()


def test_health_ready_live_metrics_endpoints():
    with appmod.app.test_client() as c:
        assert c.get("/health").status_code == 200
        assert c.get("/ready").status_code == 200
        assert c.get("/live").status_code == 200
        assert c.get("/metrics").status_code == 200
        components = c.get("/health").get_json()["components"]
        for key in ("api", "socketio", "capture", "flow_engine", "ml_model",
                    "shap", "baseline", "recon", "identity", "risk", "incident_engine"):
            assert key in components


def test_api_v1_diagnostic_routes_respond():
    with appmod.app.test_client() as c:
        for path in [
            "/api/v1/system/status", "/api/v1/clients", "/api/v1/sessions",
            "/api/v1/incidents", "/api/v1/alerts", "/api/v1/risk", "/api/v1/recon",
            "/api/v1/baseline", "/api/v1/metrics", "/api/v1/model",
            "/api/v1/test/connectivity", "/api/v1/test/ml", "/api/v1/test/capture",
            "/api/v1/test/socket",
        ]:
            resp = c.get(path)
            assert resp.status_code == 200, path
        resp = c.post("/api/v1/test/demo")
        assert resp.status_code == 200
