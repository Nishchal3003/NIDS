from dns_detector import DNSTunnelDetector
from dns_features import extract_stateless
from dns_attack_generator import DNSTunnelTestGenerator, TEST_DOMAIN


def test_model_loads_successfully():
    detector = DNSTunnelDetector()
    assert detector.status == "loaded"
    assert detector.model is not None


def test_classify_returns_label_and_confidence():
    detector = DNSTunnelDetector()
    features = extract_stateless("www.example.com")
    label, confidence, _ = detector.classify(features)
    assert label in {"BENIGN", "DNS_TUNNELING"}
    assert 0.0 <= confidence <= 100.0


def test_classify_on_tunneling_shaped_name_produces_a_classification():
    detector = DNSTunnelDetector()
    long_label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    features = extract_stateless(f"{long_label}.tunnel-test.invalid")
    label, confidence, _ = detector.classify(features)
    assert label in {"BENIGN", "DNS_TUNNELING"}
    assert confidence > 0.0


def test_feature_order_matches_training_metadata():
    detector = DNSTunnelDetector()
    assert len(detector.feature_order) == 11
    assert "longest_word" not in detector.feature_order
    assert "sld" not in detector.feature_order


def test_missing_model_fails_safe_to_benign():
    detector = DNSTunnelDetector(model_path="/nonexistent/path.pkl", metadata_path="/nonexistent/meta.json")
    assert detector.status.startswith("unavailable")
    label, confidence, shap_values = detector.classify(extract_stateless("www.example.com"))
    assert label == "BENIGN"
    assert confidence == 0.0
    assert shap_values is None


def test_authorized_dns_generator_shape_is_detected_as_tunneling():
    detector = DNSTunnelDetector()
    labels = DNSTunnelTestGenerator._encode_labels(0)
    fqdn = f"{'.'.join(labels)}.{TEST_DOMAIN}"
    label, confidence, _ = detector.classify(extract_stateless(fqdn))
    assert label == "DNS_TUNNELING"
    assert confidence > 0.0
