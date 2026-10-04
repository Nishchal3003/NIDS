"""Threat correlation & risk assessment.

Fuses independent detection signals -- confirmed RF attack alerts, ambient
traffic-baseline drift, and multi-window reconnaissance findings -- into a
single, decaying per-source risk score. This is purely a correlation/scoring
layer: it never fabricates a DoS/PortScan classification on its own, and it
does not gate or suppress any of the underlying signals; it only says how
worried an operator should be about a given source right now.
"""
import threading
import time
from collections import deque

SEVERITY_WEIGHTS = {
    "confirmed_attack": 70.0,  # RF-confirmed DoS/PortScan during an authorized test window
    "recon_fast": 35.0,
    "recon_medium": 25.0,
    "recon_slow": 15.0,
    "baseline_drift": 20.0,  # ambient, traffic-wide drift (not source-specific)
    "unknown_identity": 5.0,  # source has no known client/session context
}

DEFAULT_HALF_LIFE_SECONDS = 60.0


def _level_for(score, high_threshold, critical_threshold):
    if score >= critical_threshold:
        return "CRITICAL"
    if score >= high_threshold:
        return "HIGH"
    if score >= 20.0:
        return "ELEVATED"
    return "LOW"


class RiskEngine:
    def __init__(
        self,
        half_life=DEFAULT_HALF_LIFE_SECONDS,
        high_threshold=50.0,
        critical_threshold=80.0,
        max_sources=2000,
    ):
        self.lock = threading.Lock()
        self.half_life = half_life
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold
        self.max_sources = max_sources
        self.sources = {}  # source -> {"score", "last_update", "reasons": deque}
        self.events = deque(maxlen=300)  # HIGH/CRITICAL crossings only

    def _decay(self, entry, now):
        elapsed = max(now - entry["last_update"], 0.0)
        if elapsed <= 0 or entry["score"] <= 0:
            return entry["score"]
        return entry["score"] * (0.5 ** (elapsed / self.half_life))

    def record(self, source, signal, weight=None, detail=None, ts=None):
        """Add one signal occurrence for `source`. Returns the updated
        {source, score, level} record."""
        if not source:
            return None
        ts = ts if ts is not None else time.time()
        weight = SEVERITY_WEIGHTS.get(signal, 10.0) if weight is None else weight
        with self.lock:
            entry = self.sources.get(source)
            if entry is None:
                if len(self.sources) >= self.max_sources:
                    stale = min(self.sources, key=lambda s: self.sources[s]["last_update"])
                    if stale != source:
                        self.sources.pop(stale, None)
                entry = {"score": 0.0, "last_update": ts, "reasons": deque(maxlen=20)}
                self.sources[source] = entry
            decayed = self._decay(entry, ts)
            new_score = min(100.0, decayed + weight)
            entry["score"] = new_score
            entry["last_update"] = ts
            entry["reasons"].append(
                {"ts": ts, "signal": signal, "weight": weight, "detail": detail}
            )
            level = _level_for(new_score, self.high_threshold, self.critical_threshold)
            record = {
                "ts": ts,
                "source": source,
                "signal": signal,
                "score": round(new_score, 1),
                "level": level,
            }
            if level in {"HIGH", "CRITICAL"}:
                self.events.append(record)
            return record

    def profile(self, source):
        now = time.time()
        with self.lock:
            entry = self.sources.get(source)
            if not entry:
                return {"source": source, "score": 0.0, "level": "LOW", "reasons": []}
            score = self._decay(entry, now)
            return {
                "source": source,
                "score": round(score, 1),
                "level": _level_for(score, self.high_threshold, self.critical_threshold),
                "reasons": list(entry["reasons"]),
            }

    def snapshot(self, limit=50):
        now = time.time()
        with self.lock:
            profiles = []
            for source, entry in self.sources.items():
                score = self._decay(entry, now)
                profiles.append(
                    {
                        "source": source,
                        "score": round(score, 1),
                        "level": _level_for(score, self.high_threshold, self.critical_threshold),
                    }
                )
            recent_events = list(self.events)[-limit:][::-1]
        profiles.sort(key=lambda p: p["score"], reverse=True)
        return {
            "tracked_sources": len(profiles),
            "top_sources": profiles[:limit],
            "recent_high_risk_events": recent_events,
        }
