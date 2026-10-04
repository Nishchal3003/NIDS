from incidents import IncidentEngine


def test_open_creates_new_incident():
    engine = IncidentEngine()
    incident = engine.open_or_update(
        "10.0.0.1", "confirmed_attack", "CRITICAL", "DoS detected", ts=1000.0
    )
    assert incident["status"] == "OPEN"
    assert incident["event_count"] == 1
    assert engine.get(incident["id"])["id"] == incident["id"]


def test_repeat_event_updates_existing_incident_within_window():
    engine = IncidentEngine(reopen_window=60.0)
    first = engine.open_or_update("10.0.0.1", "reconnaissance", "HIGH", "Scan seen", ts=1000.0)
    second = engine.open_or_update("10.0.0.1", "reconnaissance", "HIGH", "Scan seen again", ts=1010.0)
    assert first["id"] == second["id"]
    assert second["event_count"] == 2


def test_event_outside_reopen_window_creates_new_incident():
    engine = IncidentEngine(reopen_window=30.0)
    first = engine.open_or_update("10.0.0.1", "reconnaissance", "HIGH", "Scan seen", ts=1000.0)
    second = engine.open_or_update("10.0.0.1", "reconnaissance", "HIGH", "Scan again", ts=1200.0)
    assert first["id"] != second["id"]


def test_acknowledge_and_resolve_lifecycle():
    engine = IncidentEngine()
    incident = engine.open_or_update("10.0.0.1", "risk", "HIGH", "Elevated risk", ts=1000.0)
    acknowledged = engine.acknowledge(incident["id"])
    assert acknowledged["status"] == "ACKNOWLEDGED"
    resolved = engine.resolve(incident["id"])
    assert resolved["status"] == "RESOLVED"


def test_resolved_incident_does_not_get_reused():
    engine = IncidentEngine(reopen_window=60.0)
    first = engine.open_or_update("10.0.0.1", "risk", "HIGH", "Elevated risk", ts=1000.0)
    engine.resolve(first["id"])
    second = engine.open_or_update("10.0.0.1", "risk", "HIGH", "Elevated again", ts=1010.0)
    assert second["id"] != first["id"]


def test_list_filters_by_status():
    engine = IncidentEngine()
    a = engine.open_or_update("10.0.0.1", "risk", "HIGH", "a", ts=1000.0)
    b = engine.open_or_update("10.0.0.2", "risk", "HIGH", "b", ts=1000.0)
    engine.resolve(a["id"])
    open_only = engine.list(status="open")
    assert len(open_only) == 1
    assert open_only[0]["id"] == b["id"]
