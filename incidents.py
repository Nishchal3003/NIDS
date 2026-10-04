"""Incident lifecycle engine.

Turns confirmed detections, reconnaissance findings, and HIGH/CRITICAL risk
crossings into structured, trackable incidents (OPEN -> ACKNOWLEDGED ->
RESOLVED) instead of a flat alert feed. In-memory only, consistent with the
rest of the project's "no persistent store" design (see PROJECT_GUIDE.md,
"Data lifetime and safety").
"""
import threading
import time
import uuid
from collections import deque

OPEN, ACKNOWLEDGED, RESOLVED = "OPEN", "ACKNOWLEDGED", "RESOLVED"

_SEVERITY_RANK = {"LOW": 0, "ELEVATED": 1, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _rank(severity):
    return _SEVERITY_RANK.get(str(severity).upper(), 0)


class IncidentEngine:
    def __init__(self, max_incidents=500, reopen_window=120.0):
        self.lock = threading.Lock()
        self.incidents = {}  # id -> incident dict
        self.order = deque(maxlen=max_incidents)
        self.reopen_window = reopen_window

    def open_or_update(self, source, category, severity, summary, evidence=None, ts=None):
        """category: e.g. 'confirmed_attack', 'reconnaissance', 'risk'. If an
        unresolved incident already exists for this (source, category) within
        reopen_window, update it in place instead of creating a duplicate."""
        ts = ts if ts is not None else time.time()
        with self.lock:
            existing = None
            for incident_id in reversed(self.order):
                incident = self.incidents.get(incident_id)
                if (
                    incident
                    and incident["source"] == source
                    and incident["category"] == category
                    and incident["status"] != RESOLVED
                    and ts - incident["last_seen"] <= self.reopen_window
                ):
                    existing = incident
                    break
            if existing:
                existing["last_seen"] = ts
                existing["event_count"] += 1
                if _rank(severity) > _rank(existing["severity"]):
                    existing["severity"] = severity
                existing["summary"] = summary
                existing["evidence"].append(evidence or {})
                existing["evidence"] = existing["evidence"][-10:]
                return dict(existing)

            incident_id = str(uuid.uuid4())[:8]
            incident = {
                "id": incident_id,
                "source": source,
                "category": category,
                "severity": severity,
                "summary": summary,
                "status": OPEN,
                "opened_at": ts,
                "last_seen": ts,
                "event_count": 1,
                "evidence": [evidence or {}],
            }
            self.incidents[incident_id] = incident
            self.order.append(incident_id)
            return dict(incident)

    def acknowledge(self, incident_id):
        with self.lock:
            incident = self.incidents.get(incident_id)
            if not incident:
                return None
            if incident["status"] == OPEN:
                incident["status"] = ACKNOWLEDGED
                incident["acknowledged_at"] = time.time()
            return dict(incident)

    def resolve(self, incident_id):
        with self.lock:
            incident = self.incidents.get(incident_id)
            if not incident:
                return None
            incident["status"] = RESOLVED
            incident["resolved_at"] = time.time()
            return dict(incident)

    def list(self, status=None, limit=100):
        with self.lock:
            items = [
                dict(self.incidents[i]) for i in reversed(self.order) if i in self.incidents
            ]
        if status:
            items = [i for i in items if i["status"] == status.upper()]
        return items[:limit]

    def get(self, incident_id):
        with self.lock:
            incident = self.incidents.get(incident_id)
            return dict(incident) if incident else None
