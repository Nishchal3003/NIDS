from detector import AnomalyDetector


def test_live_dos_threshold_outweighs_portscan():
    detector = AnomalyDetector()
    label, probability, _ = detector.classify_live(
        {
            "flow_packets_per_s": 80,
            "total_fwd_packets": 60,
            "destination_port": 80,
            "flow_duration_us": 1_000_000,
        },
        distinct_ports=12,
        source_syn_count=10,
    )

    assert label == "DoS"
    assert probability >= 0.85
