from risk import RiskEngine


def test_unseen_source_is_low_risk():
    engine = RiskEngine()
    profile = engine.profile("10.0.0.1")
    assert profile["score"] == 0.0
    assert profile["level"] == "LOW"


def test_confirmed_attack_pushes_to_high_or_critical():
    engine = RiskEngine()
    record = engine.record("10.0.0.2", "confirmed_attack", ts=1000.0)
    assert record["level"] in {"HIGH", "CRITICAL"}
    assert record["score"] >= 50.0


def test_signals_accumulate_for_same_source():
    engine = RiskEngine()
    engine.record("10.0.0.3", "recon_fast", ts=1000.0)
    second = engine.record("10.0.0.3", "recon_medium", ts=1001.0)
    assert second["score"] > 35.0  # more than a single recon_fast weight alone


def test_score_decays_over_time():
    engine = RiskEngine(half_life=10.0)
    engine.record("10.0.0.4", "confirmed_attack", ts=1000.0)
    later = engine.profile("10.0.0.4")
    # profile() uses current wall-clock time, so simulate decay by reading
    # the internal entry directly at a later timestamp instead.
    with engine.lock:
        entry = engine.sources["10.0.0.4"]
        decayed_score = engine._decay(entry, 1000.0 + 10.0)
    assert decayed_score < entry["score"]


def test_recent_high_risk_events_recorded_in_snapshot():
    engine = RiskEngine()
    engine.record("10.0.0.5", "confirmed_attack", ts=1000.0)
    snapshot = engine.snapshot()
    assert snapshot["tracked_sources"] == 1
    assert any(e["source"] == "10.0.0.5" for e in snapshot["recent_high_risk_events"])
