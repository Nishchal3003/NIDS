"""Structured, evidence-backed explanations for dashboard and report alerts."""


def _present(value):
    return value is not None and value != "" and str(value).lower() not in {"none", "null"}


def _first(alert, *keys):
    for key in keys:
        value = alert.get(key)
        if _present(value):
            return value
    return None


def generate_attack_explanation(alert):
    """Build the SOC explanation view from fields present on one real alert."""
    threat = str(_first(alert, "threat_type", "attack_type", "kind") or "Anomaly")
    normalized = threat.lower().replace("-", "").replace("_", "").replace(" ", "")
    is_dos = normalized in {"dos", "ddos", "flood", "synflood"}
    is_scan = normalized in {"portscan", "scan"}
    severity = str(_first(alert, "severity") or ("CRITICAL" if is_dos else "HIGH" if is_scan else "MEDIUM")).upper()
    method = str(_first(alert, "detection_method", "method") or ("Behavioural" if is_scan else "Combined"))
    features = alert.get("features") or {}
    evidence = []

    if is_scan:
        unique_ports = _first(features, "unique_destination_ports", "unique_ports")
        attempts = _first(features, "connection_attempts", "scan_attempts")
        window = _first(features, "window_seconds")
        if _present(unique_ports):
            suffix = f" within {window:g} seconds" if isinstance(window, (int, float)) else ""
            evidence.append(f"{unique_ports} unique destination ports contacted{suffix}.")
        if _present(attempts) and str(attempts) != str(unique_ports):
            evidence.append(f"{attempts} connection attempts were observed.")
        explanation = (
            "A possible port scan was detected. The source repeatedly attempted connections "
            "to multiple destination ports in a short observation window, which is consistent "
            "with service discovery or reconnaissance."
            if evidence else
            "A possible port scan was detected from repeated connection attempts. "
            "The explanation is based on limited observed indicators."
        )
        why = "The behavioural port-scan detector counts distinct destination ports contacted by one source during a rolling window."
        recommendation = "Investigate the source activity and review additional connection attempts. Consider restricting unnecessary exposed services."
    elif is_dos:
        events = _first(features, "events_last_1s")
        total = _first(features, "events_last_5s")
        interval = _first(features, "mean_interval_ms")
        if _present(events):
            evidence.append(f"{events} events observed during the last second.")
        if _present(total):
            evidence.append(f"{total} events observed in the rolling five-second window.")
        if _present(interval):
            evidence.append(f"Mean event interval: {interval} ms.")
        explanation = (
            "A Denial of Service (DoS) pattern was detected. The source generated an unusually "
            "high volume of rapid events, which can consume service resources and reduce "
            "availability for legitimate users."
            if evidence else
            "A DoS-like anomaly was detected, but the explanation is based on limited observed indicators."
        )
        why = "The detector evaluates event rate, rolling volume, interval timing, and burstiness against the trained flood model."
        recommendation = "Isolate or rate-limit the source if malicious activity is confirmed, and alert the network administrator."
    else:
        explanation = "Suspicious activity was detected, but the available alert fields do not provide enough evidence for a more specific explanation."
        why = "The alert was raised by the detection pipeline using the evidence exposed in this record."
        recommendation = "Review the source activity and related logs before taking containment action."

    detection_details = {}
    detail_map = [
        ("Threat type", threat),
        ("Severity", severity),
        ("Detection method", method),
        ("ML confidence", _first(alert, "confidence")),
        ("ML prediction", _first(alert, "prediction", "ml_prediction")),
        ("Source", _first(alert, "source", "client")),
        ("Source IP", _first(alert, "source_ip")),
        ("Destination", _first(alert, "destination")),
        ("Destination IP", _first(alert, "destination_ip")),
        ("Protocol", _first(alert, "protocol")),
        ("Source port", _first(alert, "source_port")),
        ("Destination port", _first(alert, "destination_port")),
        ("Timestamp", _first(alert, "ts")),
    ]
    for label, value in detail_map:
        if _present(value):
            detection_details[label] = value

    ml_explanation = None
    prediction = _first(alert, "prediction", "ml_prediction")
    confidence = _first(alert, "confidence")
    shap_values = alert.get("shap") or []
    if _present(prediction) or _present(confidence) or shap_values:
        ml_explanation = {
            "prediction": prediction,
            "confidence": confidence,
            "shap": shap_values,
            "message": "This alert includes output from the Random Forest model. SHAP values are shown only because the existing pipeline supplied them.",
        }
    elif method.lower() in {"behavioural", "deterministic", "rule-based"}:
        ml_explanation = {
            "message": "This detection was made by a deterministic behavioural rule — not the ML model. No SHAP explanation applies. The evidence above is direct application-level observation."
        }

    observed = _first(alert, "observed_rule", "rule_observation")
    return {
        "severity": severity,
        "threatType": threat,
        "source": _first(alert, "source", "client"),
        "destination": _first(alert, "destination"),
        "timestamp": _first(alert, "ts"),
        "detectionMethod": method,
        "explanation": explanation,
        "detectionDetails": detection_details,
        "evidence": evidence,
        "recommendedAction": recommendation,
        "whyFlagged": why,
        "observed": observed,
        "mlExplanation": ml_explanation,
        "isRuleBased": method.lower() in {"behavioural", "deterministic", "rule-based"},
    }
