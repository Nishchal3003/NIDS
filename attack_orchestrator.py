"""Random attack-test orchestration for the single "LAUNCH ATTACK" control.

Owns exactly one responsibility: given an authorized attacker session,
randomly select one of the allowed attack-test types, start its bounded
generator, and keep a test-run record for audit/correlation. It:

  * NEVER selects a type and hands it to the detector -- the generator just
    starts real, bounded traffic; the existing independent detection
    pipeline (capture -> features -> model -> risk -> incident) decides
    what, if anything, it actually is.
  * NEVER emits a "detected" event itself.
  * Only correlates a later, independently-produced detection result back
    onto the matching test run (see note_detection), purely for audit/demo
    metrics -- this correlation never feeds back into the detection logic.

Configuration (environment variables, all optional):
    ATTACK_AUTOMATION_ENABLED   "1"/"0" (default "1")
    ATTACK_COOLDOWN_SECONDS     minimum seconds between launches (default 10)
    ATTACK_MIN_DELAY_SECONDS    reserved for a future auto/continuous mode;
    ATTACK_MAX_DELAY_SECONDS    not used by the single-click launch path
    ALLOWED_ATTACK_TYPES        comma list, default "DOS,PORTSCAN,DNS_TUNNEL"
    ATTACK_CORRELATION_TIMEOUT_SECONDS  how long a run stays PENDING (default 30)
"""
import os
import secrets
import threading
import time
import uuid

DOS, PORTSCAN, DNS_TUNNEL = "DOS", "PORTSCAN", "DNS_TUNNEL"
ALL_TYPES = (DOS, PORTSCAN, DNS_TUNNEL)
PUBLIC_LABELS = {DOS: "DoS", PORTSCAN: "PortScan", DNS_TUNNEL: "DNS Tunneling"}

# Canonicalizes whatever label the detection pipeline actually reports
# ("DoS", "PortScan", "DNS_TUNNELING", ...) onto the same vocabulary used
# for test-run selection, so MATCH/MISS comparison is well-defined.
_CANONICAL = {
    "DOS": DOS, "PORTSCAN": PORTSCAN, "DNS_TUNNEL": DNS_TUNNEL, "DNS_TUNNELING": DNS_TUNNEL,
}


def _canon(label):
    return _CANONICAL.get(str(label).strip().upper().replace(" ", "_"), str(label).strip().upper())


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


class AttackOrchestrator:
    def __init__(self, runners, allowed_types=None, cooldown_seconds=None, enabled=None):
        """runners: {DOS: callable(test_run_id, attacker_session_id,
        attacker_source_ip) -> status_dict, PORTSCAN: ..., DNS_TUNNEL: ...}.
        Each runner must only start its bounded generator and return a
        status dict -- it must never emit a detection."""
        self.runners = runners
        self.enabled = _env_bool("ATTACK_AUTOMATION_ENABLED", True) if enabled is None else enabled
        self.cooldown_seconds = (
            float(os.getenv("ATTACK_COOLDOWN_SECONDS", "10")) if cooldown_seconds is None else cooldown_seconds
        )
        self.min_delay_seconds = float(os.getenv("ATTACK_MIN_DELAY_SECONDS", "0"))
        self.max_delay_seconds = float(os.getenv("ATTACK_MAX_DELAY_SECONDS", "0"))
        self.correlation_timeout = float(os.getenv("ATTACK_CORRELATION_TIMEOUT_SECONDS", "30"))

        configured = allowed_types
        if configured is None:
            configured = [c.strip().upper() for c in os.getenv(
                "ALLOWED_ATTACK_TYPES", ",".join(ALL_TYPES)
            ).split(",") if c.strip()]
        self.allowed_types = [t for t in configured if t in runners]
        if not self.allowed_types:
            raise ValueError(
                "no allowed attack types have a configured runner "
                f"(configured={configured!r}, runners={list(runners)!r})"
            )

        self.lock = threading.Lock()
        self.runs = {}
        self.order = []
        self.last_launch_ts = 0.0
        self.total_tests = 0
        self._selection_pool = []

    def _next_type(self):
        """Return a randomized type, forcing DNS tunneling every third launch."""
        next_launch = self.total_tests + 1
        if next_launch % 3 == 0 and DNS_TUNNEL in self.allowed_types:
            self._selection_pool = []
            return DNS_TUNNEL

        random_types = [attack_type for attack_type in self.allowed_types if attack_type != DNS_TUNNEL]
        if not random_types:
            random_types = list(self.allowed_types)
        if not self._selection_pool:
            self._selection_pool = random_types
            secrets.SystemRandom().shuffle(self._selection_pool)
        return self._selection_pool.pop()

    def launch(self, attacker_session_id, attacker_source_ip=None):
        """Randomly select one allowed type and start it.

        The selected type is returned as launch metadata so the authorized
        attacker can verify which bounded generator actually ran. Detection
        remains independent and is reported later through note_detection().
        """
        if not self.enabled:
            return {"ok": False, "error": "attack automation is disabled"}
        now = time.time()
        with self.lock:
            if now - self.last_launch_ts < self.cooldown_seconds:
                remaining = round(self.cooldown_seconds - (now - self.last_launch_ts), 1)
                return {"ok": False, "error": f"cooldown active, try again in {remaining}s"}
            selected = self._next_type()
            test_run_id = f"TEST-{uuid.uuid4().hex[:8]}"
            record = {
                "test_run_id": test_run_id,
                "requested_at": now,
                "attacker_session": attacker_session_id,
                "attacker_source_ip": attacker_source_ip,
                "selected_test_type": selected,
                "started_at": None,
                "generator_status": None,
                "detected_at": None,
                "detected_type": None,
                "detection_confidence": None,
                "incident_id": None,
                "result": "PENDING",
            }
            self.runs[test_run_id] = record
            self.order.append(test_run_id)
            self.total_tests += 1
            if len(self.order) > 200:
                self.runs.pop(self.order.pop(0), None)
            self.last_launch_ts = now

        try:
            status = self.runners[selected](test_run_id, attacker_session_id, attacker_source_ip)
        except Exception as exc:
            with self.lock:
                record["result"] = "ERROR"
                record["generator_status"] = {"error": f"{type(exc).__name__}: {exc}"}
            return {"ok": False, "error": str(exc), "test_run_id": test_run_id}

        with self.lock:
            record["started_at"] = time.time()
            record["generator_status"] = status
        return {
            "ok": True,
            "test_run_id": test_run_id,
            "attack_type": PUBLIC_LABELS[selected],
            "generator_status": status,
        }

    def note_detection(self, source_ip, detected_type, confidence, incident_id, ts=None):
        """Called by app.py once the independent detection pipeline produces
        a result. Matches it to the most recent PENDING run from the same
        attacker source within the correlation window, purely for test
        metadata -- never influences the detection itself."""
        ts = ts if ts is not None else time.time()
        canonical_detected = _canon(detected_type)
        with self.lock:
            self._expire_timeouts(ts)
            candidate = None
            for test_run_id in reversed(self.order):
                record = self.runs.get(test_run_id)
                if not record or record["result"] != "PENDING":
                    continue
                if record.get("attacker_source_ip") and source_ip and record["attacker_source_ip"] != source_ip:
                    continue
                if ts - record["requested_at"] > self.correlation_timeout:
                    continue
                candidate = record
                break
            if not candidate:
                return None
            candidate["detected_at"] = ts
            candidate["detected_type"] = canonical_detected
            candidate["detection_confidence"] = confidence
            candidate["incident_id"] = incident_id
            candidate["result"] = "MATCH" if canonical_detected == candidate["selected_test_type"] else "MISS"
            return dict(candidate)

    def _expire_timeouts(self, now=None):
        now = now if now is not None else time.time()
        for test_run_id in self.order:
            record = self.runs.get(test_run_id)
            if record and record["result"] == "PENDING" and now - record["requested_at"] > self.correlation_timeout:
                record["result"] = "MISS"

    def get(self, test_run_id):
        with self.lock:
            self._expire_timeouts()
            record = self.runs.get(test_run_id)
            return dict(record) if record else None

    def latest(self):
        with self.lock:
            self._expire_timeouts()
            if not self.order:
                return None
            return dict(self.runs[self.order[-1]])

    def snapshot(self, limit=20):
        with self.lock:
            self._expire_timeouts()
            return {
                "enabled": self.enabled,
                "allowed_types": self.allowed_types,
                "cooldown_seconds": self.cooldown_seconds,
                "total_tests": self.total_tests,
                "recent_runs": [dict(self.runs[i]) for i in self.order[-limit:]][::-1],
            }
