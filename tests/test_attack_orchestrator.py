import time

import pytest

from attack_orchestrator import AttackOrchestrator, DOS, PORTSCAN, DNS_TUNNEL


def _runners(log):
    def make(kind):
        def runner(test_run_id, attacker_session_id, attacker_source_ip):
            log.append((kind, test_run_id, attacker_session_id, attacker_source_ip))
            return {"kind": kind, "test_run_id": test_run_id}
        return runner
    return {DOS: make(DOS), PORTSCAN: make(PORTSCAN), DNS_TUNNEL: make(DNS_TUNNEL)}


def test_launch_selects_exactly_one_runner():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    result = orch.launch("sid-1", "10.0.0.5")
    assert result["ok"] is True
    assert len(log) == 1
    assert log[0][0] in {DOS, PORTSCAN, DNS_TUNNEL}


def test_launch_never_reveals_selected_type_to_caller():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    result = orch.launch("sid-1", "10.0.0.5")
    assert result["attack_type"] in {"DoS", "PortScan", "DNS Tunneling"}
    assert "selected_test_type" not in result
    assert "kind" not in result


def test_selected_type_is_always_one_of_three():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    seen = set()
    for _ in range(40):
        orch.last_launch_ts = 0  # bypass cooldown for this distribution check
        result = orch.launch("sid-1", "10.0.0.5")
        run = orch.get(result["test_run_id"])
        seen.add(run["selected_test_type"])
    assert seen <= {DOS, PORTSCAN, DNS_TUNNEL}
    assert len(seen) > 1  # over 40 draws we should see more than one type


def test_randomized_cycle_launches_every_enabled_type_once():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    for _ in range(3):
        orch.last_launch_ts = 0
        assert orch.launch("sid-1", "10.0.0.5")["ok"] is True
    assert {entry[0] for entry in log} == {DOS, PORTSCAN, DNS_TUNNEL}


def test_cooldown_rejects_rapid_repeat_launch():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=30)
    first = orch.launch("sid-1", "10.0.0.5")
    assert first["ok"] is True
    second = orch.launch("sid-1", "10.0.0.5")
    assert second["ok"] is False
    assert "cooldown" in second["error"]


def test_disabled_orchestrator_rejects_launch():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0, enabled=False)
    result = orch.launch("sid-1", "10.0.0.5")
    assert result["ok"] is False
    assert "disabled" in result["error"]


def test_orchestrator_never_calls_a_detection_callback():
    """The orchestrator has no detection-reporting hook at all -- the only
    way a result gets attached to a run is via note_detection, called by
    app.py's real, independent detection pipeline."""
    orch = AttackOrchestrator.__init__
    import inspect
    sig = inspect.signature(orch)
    assert "on_detect" not in sig.parameters
    assert "detector" not in sig.parameters


def test_note_detection_matches_pending_run_and_computes_match():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    launch_result = orch.launch("sid-1", "10.0.0.5")
    test_run_id = launch_result["test_run_id"]
    run = orch.get(test_run_id)
    selected = run["selected_test_type"]
    detected_label = {"DOS": "DoS", "PORTSCAN": "PortScan", "DNS_TUNNEL": "DNS_TUNNELING"}[selected]

    correlated = orch.note_detection("10.0.0.5", detected_label, 96.0, "INC-0001")
    assert correlated["result"] == "MATCH"
    assert correlated["incident_id"] == "INC-0001"


def test_note_detection_computes_miss_on_mismatch():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    launch_result = orch.launch("sid-1", "10.0.0.5")
    run = orch.get(launch_result["test_run_id"])
    selected = run["selected_test_type"]
    wrong_label = {"DOS": "PortScan", "PORTSCAN": "DoS", "DNS_TUNNEL": "DoS"}[selected]

    correlated = orch.note_detection("10.0.0.5", wrong_label, 90.0, "INC-0002")
    assert correlated["result"] == "MISS"


def test_note_detection_ignores_unrelated_source_ip():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    orch.launch("sid-1", "10.0.0.5")
    correlated = orch.note_detection("10.0.0.99", "DoS", 90.0, "INC-0003")
    assert correlated is None


def test_pending_run_expires_to_miss_after_correlation_timeout():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0, )
    orch.correlation_timeout = 0.05
    launch_result = orch.launch("sid-1", "10.0.0.5")
    time.sleep(0.1)
    run = orch.get(launch_result["test_run_id"])
    assert run["result"] == "MISS"


def test_allowed_types_can_be_restricted():
    log = []
    orch = AttackOrchestrator(_runners(log), allowed_types=[DOS, PORTSCAN], cooldown_seconds=0)
    for _ in range(10):
        orch.last_launch_ts = 0
        result = orch.launch("sid-1", "10.0.0.5")
        run = orch.get(result["test_run_id"])
        assert run["selected_test_type"] in {DOS, PORTSCAN}


def test_allowed_type_without_a_runner_is_dropped_not_fatal():
    # PORTSCAN has no runner here -- it's silently excluded, not an error,
    # as long as at least one allowed type still has a runner.
    orch = AttackOrchestrator({DOS: lambda test_run_id: {}}, allowed_types=[DOS, PORTSCAN], cooldown_seconds=0)
    assert orch.allowed_types == [DOS]


def test_no_runners_at_all_raises():
    with pytest.raises(ValueError):
        AttackOrchestrator({}, allowed_types=[DOS, PORTSCAN])


def test_runner_receives_session_and_source_ip():
    log = []
    orch = AttackOrchestrator(_runners(log), cooldown_seconds=0)
    orch.launch("sid-42", "10.0.0.77")
    assert log[0][2] == "sid-42"
    assert log[0][3] == "10.0.0.77"
