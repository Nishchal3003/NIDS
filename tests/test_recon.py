from recon import ReconEngine


def test_fast_burst_scan_is_detected():
    engine = ReconEngine(report_cooldown=0)
    finding = None
    for port in range(1, 6):
        finding = engine.observe("10.0.0.5", port, ts=1000.0 + port * 0.1)
    assert finding is not None
    assert finding["stage"] == "fast"
    assert finding["window_counts"]["fast"] >= 4


def test_low_rate_traffic_is_not_flagged():
    engine = ReconEngine(report_cooldown=0)
    finding = engine.observe("10.0.0.9", 443, ts=1000.0)
    assert finding is None
    finding = engine.observe("10.0.0.9", 443, ts=1001.0)
    assert finding is None


def test_slow_scan_over_wider_window_is_detected():
    engine = ReconEngine(report_cooldown=0)
    finding = None
    base = 2000.0
    # 20 distinct ports spread across ~170 seconds: too slow to trip the
    # 5s/30s windows, but should trip the 180s "slow" window.
    for i in range(20):
        finding = engine.observe("10.0.0.7", 2000 + i, ts=base + i * 8.5)
    assert finding is not None
    assert finding["stage"] == "slow"


def test_report_cooldown_suppresses_repeat_findings():
    engine = ReconEngine(report_cooldown=30.0)
    findings = [
        engine.observe("10.0.0.5", port, ts=1000.0 + port * 0.1) for port in range(1, 6)
    ]
    triggered = [f for f in findings if f is not None]
    assert len(triggered) == 1  # only the first crossing was reported; cooldown suppressed the rest
    again = engine.observe("10.0.0.5", 999, ts=1000.6)
    assert again is None
