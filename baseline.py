"""Adaptive traffic baseline and concept-drift detection.

This module answers a question the existing detector does not: "does the
network still look like the network we've been observing?" It is
deliberately independent from the CICIDS Random Forest and from the
authorized-attack-window alerting in app.py/capture.py.

Design constraints carried over from the rest of the project:
  * In-memory only, bounded history (see PROJECT_GUIDE.md "Data lifetime").
  * Ambient traffic must never be promoted to a DoS/PortScan attack alert;
    that stays reserved for the authorized packet-test path. Drift findings
    here are surfaced as their own category ("baseline_drift"), never
    relabeled as an attack.
  * No new external dependencies — pure standard library.

Two techniques, combined:
  * Per-metric EWMA mean/variance -> a z-score per metric, so an operator
    can see *which* aspect of traffic moved (rate, port spread, SYN mix...).
  * A Page-Hinkley test on the combined anomaly score -> a robust "has the
    traffic level genuinely and persistently shifted" signal, which is less
    twitchy than thresholding a single noisy window.
"""
import math
import threading
import time
from collections import deque


class EWMAStat:
    """Exponentially weighted moving mean/variance for one scalar metric."""

    def __init__(self, alpha=0.05):
        self.alpha = alpha
        self.mean = None
        self.var = 0.0
        self.n = 0

    def update(self, value):
        value = float(value)
        if self.mean is None:
            self.mean = value
            self.var = 0.0
        else:
            diff = value - self.mean
            increment = self.alpha * diff
            self.mean += increment
            # Welford-style EWMA variance update.
            self.var = (1 - self.alpha) * (self.var + diff * increment)
        self.n += 1

    @property
    def std(self):
        return math.sqrt(self.var) if self.var > 0 else 0.0

    def zscore(self, value):
        if self.mean is None:
            return 0.0
        # Real traffic always has some jitter, but a metric can look
        # perfectly constant over a short/synthetic warmup (std == 0).
        # Floor the denominator so a genuine jump off a flat baseline still
        # registers instead of silently dividing to a zero z-score forever.
        denom = max(self.std, abs(self.mean) * 0.05, 1e-6)
        return (float(value) - self.mean) / denom


class TrafficBaseline:
    """Tracks per-window ambient traffic metrics and flags drift from them.

    Expected input windows (see capture.py's metrics loop), one dict per
    ~1 second of observed live traffic:
        {
            "packets_per_s": float,
            "bytes_per_s": float,
            "unique_sources": int,
            "unique_dest_ports": int,
            "syn_ratio": float,   # SYN packets / total packets, 0..1
        }
    """

    METRICS = (
        "packets_per_s",
        "bytes_per_s",
        "unique_sources",
        "unique_dest_ports",
        "syn_ratio",
    )

    def __init__(
        self,
        alpha=0.05,
        warmup_windows=30,
        drift_zscore_threshold=6.0,
        ph_delta=0.005,
        ph_lambda=20.0,
        history_seconds=1800,
        min_drift_gap_seconds=15.0,
    ):
        self.lock = threading.Lock()
        self.stats = {name: EWMAStat(alpha=alpha) for name in self.METRICS}
        self.warmup_windows = warmup_windows
        self.windows_seen = 0
        self.drift_zscore_threshold = drift_zscore_threshold
        self.min_drift_gap_seconds = min_drift_gap_seconds

        # Page-Hinkley cumulative-drift test state, run over the combined score.
        self.ph_delta = ph_delta
        self.ph_lambda = ph_lambda
        self.ph_sum = 0.0
        self.ph_min = 0.0
        self.ph_mean = 0.0
        self.ph_n = 0

        self.history = deque(maxlen=max(history_seconds, 60))
        self.last_drift_ts = 0.0
        self.drift_event_count = 0

    def observe(self, metrics, ts=None):
        """Feed one aggregation window and return its scored record."""
        ts = ts if ts is not None else time.time()
        with self.lock:
            zscores = {}
            in_warmup = self.windows_seen < self.warmup_windows
            for name in self.METRICS:
                value = metrics.get(name, 0.0) or 0.0
                stat = self.stats[name]
                zscores[name] = 0.0 if in_warmup else stat.zscore(value)
                stat.update(value)
            self.windows_seen += 1

            score = (
                math.sqrt(sum(z * z for z in zscores.values()) / len(zscores))
                if zscores
                else 0.0
            )

            drift = False
            if not in_warmup:
                cumulative_drift = self._page_hinkley_update(score)
                threshold_drift = score >= self.drift_zscore_threshold
                drift = cumulative_drift or threshold_drift
                if drift and (ts - self.last_drift_ts) < self.min_drift_gap_seconds:
                    # Still real drift, but suppress duplicate "new event"
                    # bookkeeping inside the same short burst.
                    self.drift_event_count += 0
                elif drift:
                    self.last_drift_ts = ts
                    self.drift_event_count += 1
                    # A confirmed, reported drift resets the cumulative test so
                    # the baseline can re-settle around the new normal instead
                    # of alerting on every subsequent window forever.
                    self._reset_page_hinkley()

            record = {
                "ts": ts,
                "score": round(score, 3),
                "drift": bool(drift),
                "warmup": in_warmup,
                "zscores": {k: round(v, 3) for k, v in zscores.items()},
                "metrics": {k: metrics.get(k, 0.0) for k in self.METRICS},
            }
            self.history.append(record)
            return record

    def _page_hinkley_update(self, score):
        self.ph_n += 1
        self.ph_mean += (score - self.ph_mean) / self.ph_n
        self.ph_sum += score - self.ph_mean - self.ph_delta
        self.ph_min = min(self.ph_min, self.ph_sum)
        return (self.ph_sum - self.ph_min) > self.ph_lambda

    def _reset_page_hinkley(self):
        self.ph_sum = 0.0
        self.ph_min = 0.0
        self.ph_mean = 0.0
        self.ph_n = 0

    def snapshot(self):
        """Current baseline state, for /api/baseline and the dashboard."""
        with self.lock:
            baseline = {
                name: {
                    "mean": round(stat.mean, 4) if stat.mean is not None else None,
                    "std": round(stat.std, 4),
                }
                for name, stat in self.stats.items()
            }
            recent = self.history[-1] if self.history else None
            return {
                "windows_seen": self.windows_seen,
                "warmup_windows": self.warmup_windows,
                "in_warmup": self.windows_seen < self.warmup_windows,
                "baseline": baseline,
                "current": recent,
                "drift_active": bool(recent and recent.get("drift")),
                "drift_event_count": self.drift_event_count,
                "last_drift_ts": self.last_drift_ts or None,
            }

    def recent_history(self, seconds=120):
        cutoff = time.time() - seconds
        with self.lock:
            return [record for record in self.history if record["ts"] >= cutoff]
