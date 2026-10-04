"""Multi-window reconnaissance detection.

The existing single 5-second port-diversity window in capture.py stays
untouched -- it directly feeds the CICIDS Random Forest's `distinct_ports`
evidence for the authorized-attack-window PortScan classification, and this
module must not change that path.

This module adds *additional*, longer windows so slow/stealthy scans (many
destination ports probed over minutes rather than seconds) become visible
as their own signal, without altering the RF decision path or the
authorized-attack-window gating. Findings here feed the risk/correlation
layer (risk.py), not the confirmed-attack alert feed.
"""
import threading
import time
from collections import defaultdict, deque


class ReconEngine:
    # (label, window_seconds, distinct-port threshold to call it "scanning")
    WINDOWS = (
        ("fast", 5, 4),
        ("medium", 30, 10),
        ("slow", 180, 20),
    )

    def __init__(self, max_sources=2000, report_cooldown=20.0):
        self.lock = threading.Lock()
        self.events = defaultdict(deque)  # source -> deque[(ts, port)]
        self.last_report = {}  # source -> ts of last emitted finding
        self.max_sources = max_sources
        self.report_cooldown = report_cooldown
        self.findings = deque(maxlen=500)

    def observe(self, source, destination_port, ts=None):
        """Record one packet's (source, destination_port). Returns a finding
        dict if this source now looks like it's scanning and hasn't been
        reported in the last `report_cooldown` seconds, else None."""
        if not source or not destination_port:
            return None
        ts = ts if ts is not None else time.time()
        longest_window = self.WINDOWS[-1][1]
        with self.lock:
            dq = self.events[source]
            dq.append((ts, destination_port))
            cutoff = ts - longest_window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            if len(self.events) > self.max_sources:
                # Bounded memory: drop the source with the oldest last-seen
                # packet rather than growing forever.
                stale_source = min(
                    self.events,
                    key=lambda s: self.events[s][-1][0] if self.events[s] else 0.0,
                )
                if stale_source != source:
                    self.events.pop(stale_source, None)
                    self.last_report.pop(stale_source, None)

            window_counts = {}
            stage = None
            for label, seconds, threshold in self.WINDOWS:
                window_start = ts - seconds
                distinct = len({port for (t, port) in dq if t >= window_start})
                window_counts[label] = distinct
                if distinct >= threshold:
                    stage = label  # widest window that currently qualifies wins

            if stage is None:
                return None
            if ts - self.last_report.get(source, 0.0) < self.report_cooldown:
                return None
            self.last_report[source] = ts
            finding = {
                "ts": ts,
                "source": source,
                "stage": stage,
                "window_counts": window_counts,
            }
            self.findings.append(finding)
            return finding

    def diagnostics(self, limit=20):
        with self.lock:
            return {
                "tracked_sources": len(self.events),
                "recent_findings": list(self.findings)[-limit:][::-1],
            }
