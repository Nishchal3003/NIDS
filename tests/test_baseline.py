from baseline import TrafficBaseline


def _steady_metrics():
    return {
        "packets_per_s": 50.0,
        "bytes_per_s": 6000.0,
        "unique_sources": 3,
        "unique_dest_ports": 4,
        "syn_ratio": 0.1,
    }


def test_no_drift_during_warmup():
    baseline = TrafficBaseline(warmup_windows=10)
    last = None
    for _ in range(10):
        last = baseline.observe(_steady_metrics())
    assert last["warmup"] is True
    assert last["drift"] is False


def test_no_drift_on_steady_traffic_after_warmup():
    baseline = TrafficBaseline(warmup_windows=10)
    for _ in range(10):
        baseline.observe(_steady_metrics())
    record = None
    for _ in range(20):
        record = baseline.observe(_steady_metrics())
    assert record["warmup"] is False
    assert record["drift"] is False
    assert record["score"] < 1.0


def test_sustained_shift_is_flagged_as_drift():
    baseline = TrafficBaseline(warmup_windows=10, drift_zscore_threshold=6.0, ph_lambda=20.0)
    for _ in range(10):
        baseline.observe(_steady_metrics())
    for _ in range(10):
        baseline.observe(_steady_metrics())

    surge = {
        "packets_per_s": 5000.0,
        "bytes_per_s": 900000.0,
        "unique_sources": 200,
        "unique_dest_ports": 60,
        "syn_ratio": 0.95,
    }
    drift_seen = False
    for _ in range(10):
        record = baseline.observe(surge)
        drift_seen = drift_seen or record["drift"]
    assert drift_seen


def test_snapshot_and_recent_history_shapes():
    baseline = TrafficBaseline(warmup_windows=2)
    baseline.observe(_steady_metrics())
    baseline.observe(_steady_metrics())
    snapshot = baseline.snapshot()
    assert snapshot["windows_seen"] == 2
    assert set(baseline.METRICS).issubset(snapshot["baseline"].keys())
    history = baseline.recent_history(seconds=3600)
    assert len(history) == 2
