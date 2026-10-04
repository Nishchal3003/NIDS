"""Live DNS feature extraction + sliding-window aggregation.

Stateless (per-query) features are computed directly from a queried FQDN
string, using only the CIC-Bell-DNS-EXF-2021 stateless_features-*.csv
columns that are unambiguous, purely numeric character/length statistics:
subdomain_length, upper, lower, numeric, special, entropy, labels,
labels_max, labels_average, len, subdomain.

Three dataset columns are excluded, explicitly rather than silently:
`FQDN_count` and `sld` do not reconstruct unambiguously from a live query
name, and `longest_word` is actually the longest *dictionary word* found by
an offline NLP word-segmentation pass over the domain (its values are text
like "microsoft"/"local"/"C", not a length) -- reproducing that live would
require bundling a word-segmentation dictionary for no detection benefit
`labels_max` already captures "longest DNS label by length". See
dns/FEATURE_MAPPING.md for the full dataset -> live -> model mapping.
"""
import math
import threading
import time
from collections import Counter, deque

STATELESS_FEATURES = (
    "subdomain_length", "upper", "lower", "numeric", "special", "entropy",
    "labels", "labels_max", "labels_average", "len", "subdomain",
)


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_stateless(fqdn):
    """fqdn: e.g. 'a1b2c3.test.example.com' (trailing dot optional). Returns
    the STATELESS_FEATURES dict -- every value is computable from the query
    name alone, exactly as it would be live from a captured DNS packet."""
    fqdn = (fqdn or "").strip().rstrip(".")
    labels_list = [label for label in fqdn.split(".") if label]
    if not labels_list:
        return {name: 0 for name in STATELESS_FEATURES}
    # Everything but the last two labels is treated as "subdomain" -- a
    # simplification (no public-suffix-list parsing) appropriate for this
    # controlled test environment's single configured test domain.
    subdomain_labels = labels_list[:-2] if len(labels_list) > 2 else []
    subdomain = ".".join(subdomain_labels)
    upper = sum(c.isupper() for c in fqdn)
    lower = sum(c.islower() for c in fqdn)
    numeric = sum(c.isdigit() for c in fqdn)
    special = sum((not c.isalnum()) and c != "." for c in fqdn)
    label_lengths = [len(label) for label in labels_list]
    return {
        "subdomain_length": len(subdomain),
        "upper": upper,
        "lower": lower,
        "numeric": numeric,
        "special": special,
        "entropy": round(_shannon_entropy(fqdn), 6),
        "labels": len(labels_list),
        "labels_max": max(label_lengths),
        "labels_average": round(sum(label_lengths) / len(label_lengths), 4),
        "len": len(fqdn),
        "subdomain": 1 if subdomain_labels else 0,
    }


class DNSWindowTracker:
    """Per-source sliding window so slow/low-and-slow tunneling (many
    individually-plausible queries) is judged on aggregate behaviour rather
    than a single query. The classifier itself still runs per query; this
    only smooths/corroborates its verdicts over a window (majority-style
    ratio), matching the dataset's stated stateless-vs-stateful distinction
    without inventing live-unobservable fields such as unique_country or
    unique_asn (see dns/FEATURE_MAPPING.md)."""

    def __init__(self, window_seconds=60.0, min_queries=5, suspicious_ratio=0.5):
        self.window_seconds = window_seconds
        self.min_queries = min_queries
        self.suspicious_ratio = suspicious_ratio
        self.lock = threading.Lock()
        self.events = {}  # source -> deque[(ts, fqdn, is_suspicious, confidence)]

    def observe(self, source, fqdn, is_suspicious, confidence, ts=None):
        ts = ts if ts is not None else time.time()
        with self.lock:
            dq = self.events.setdefault(source, deque())
            dq.append((ts, fqdn, bool(is_suspicious), float(confidence)))
            cutoff = ts - self.window_seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            total = len(dq)
            suspicious = sum(1 for e in dq if e[2])
            distinct_names = len({e[1] for e in dq})
            mean_conf = (sum(e[3] for e in dq if e[2]) / suspicious) if suspicious else 0.0
            window_flag = total >= self.min_queries and (suspicious / total) >= self.suspicious_ratio
            return {
                "source": source,
                "ts": ts,
                "window_total": total,
                "window_suspicious": suspicious,
                "distinct_names": distinct_names,
                "window_ratio": round(suspicious / total, 3) if total else 0.0,
                "window_flag": window_flag,
                "mean_confidence": round(mean_conf, 2),
            }

    def diagnostics(self):
        with self.lock:
            return {"tracked_sources": len(self.events)}
