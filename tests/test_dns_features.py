from dns_features import extract_stateless, DNSWindowTracker, STATELESS_FEATURES


def test_extract_stateless_returns_all_expected_keys():
    features = extract_stateless("abc123.sub.example.com")
    assert set(features.keys()) == set(STATELESS_FEATURES)


def test_bare_registrable_domain_has_no_subdomain_signal():
    features = extract_stateless("example.com")
    assert features["subdomain"] == 0
    assert features["subdomain_length"] == 0


def test_single_subdomain_label_is_flagged():
    features = extract_stateless("www.example.com")
    assert features["subdomain"] == 1


def test_long_encoded_subdomain_has_high_entropy_and_subdomain_flag():
    long_label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    features = extract_stateless(f"{long_label}.tunnel-test.example.com")
    assert features["subdomain"] == 1
    assert features["subdomain_length"] >= len(long_label)
    assert features["entropy"] > 2.0


def test_empty_fqdn_returns_zeroed_features():
    features = extract_stateless("")
    assert all(v == 0 for v in features.values())


def test_window_tracker_flags_sustained_suspicious_ratio():
    tracker = DNSWindowTracker(window_seconds=60, min_queries=5, suspicious_ratio=0.5)
    result = None
    for i in range(6):
        result = tracker.observe("10.0.0.9", f"query{i}.test", True, 92.0, ts=1000.0 + i)
    assert result["window_flag"] is True
    assert result["window_total"] == 6


def test_window_tracker_does_not_flag_mostly_benign_traffic():
    tracker = DNSWindowTracker(window_seconds=60, min_queries=5, suspicious_ratio=0.5)
    result = None
    for i in range(10):
        suspicious = i == 0  # only one suspicious query out of ten
        result = tracker.observe("10.0.0.9", f"query{i}.test", suspicious, 90.0, ts=1000.0 + i)
    assert result["window_flag"] is False


def test_window_tracker_respects_window_seconds_expiry():
    tracker = DNSWindowTracker(window_seconds=10, min_queries=3, suspicious_ratio=0.5)
    tracker.observe("10.0.0.9", "a.test", True, 90.0, ts=1000.0)
    tracker.observe("10.0.0.9", "b.test", True, 90.0, ts=1001.0)
    result = tracker.observe("10.0.0.9", "c.test", True, 90.0, ts=1050.0)  # far outside window
    assert result["window_total"] == 1
