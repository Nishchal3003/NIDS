# DNS Tunneling Feature Mapping — CIC-Bell-DNS-EXF-2021

This document is the explicit dataset → live-packet → model-feature mapping
required before any DNS tunneling detector is trained or shipped. It exists
so the model and the live extractor are provably using the same feature
semantics (see `ml/train_dns_model.py` and `dns_features.py`, which both
import `STATELESS_FEATURES` from the same source of truth).

## Dataset

**CIC-Bell-DNS-EXF-2021** (Canadian Institute for Cybersecurity / Bell
Canada), supplied as per-query **stateless** feature CSVs and windowed
**stateful** feature CSVs, for both attack (DNS tunneling/exfiltration) and
benign DNS traffic, at "light" and "heavy" traffic-volume variants.

Files used for this phase (bundled under `dataset/dns/`):

- `Attacks/stateless_features-light_{audio,compressed,exe,image,text,video}.pcap.csv`
  — six payload-type variants, all labeled `DNS_TUNNELING`
- `Benign/stateless_features-light_benign.pcap.csv` — labeled `BENIGN`

The "heavy" variants and the `stateful_features-*.csv` files were inspected
(see below) but are **not** used for the live classifier in this phase — see
"Stateful features — excluded from the trained classifier" below for why,
and "Extending this" for how to add the heavy set.

## Stateless (per-query) feature mapping

| Dataset column | Meaning | Live packet feature | Model feature |
|---|---|---|---|
| `len` | full FQDN length | `len(fqdn)` from the captured `DNSQR.qname` | `len` |
| `subdomain_length` | length of the subdomain portion | labels before the last two, rejoined and measured | `subdomain_length` |
| `upper` | count of uppercase chars | `sum(c.isupper() for c in fqdn)` | `upper` |
| `lower` | count of lowercase chars | `sum(c.islower() for c in fqdn)` | `lower` |
| `numeric` | count of digit chars | `sum(c.isdigit() for c in fqdn)` | `numeric` |
| `special` | count of non-alphanumeric chars (excl. `.`) | computed the same way | `special` |
| `entropy` | Shannon entropy of the FQDN string | computed the same way (base-2) | `entropy` |
| `labels` | number of dot-separated labels | `len(fqdn.split('.'))` | `labels` |
| `labels_max` | longest label length | `max(len(l) for l in labels)` | `labels_max` |
| `labels_average` | mean label length | `mean(len(l) for l in labels)` | `labels_average` |
| `subdomain` | whether a subdomain exists | `1` if more than 2 labels | `subdomain` |

All eleven are:
1. present in the dataset,
2. computable from nothing but the DNS query name as captured live, and
3. computed identically in `ml/train_dns_model.py` (via the dataset's own
   columns) and `dns_features.extract_stateless()` (via the live `DNSQR`).

## Excluded dataset columns (explicitly, not silently)

| Dataset column | Why excluded |
|---|---|
| `FQDN_count` | The published value (e.g. `26` for a 13-character FQDN in the sample row) does not match any documented definition the project could verify against the raw FQDN length; rather than guess, it is left out of both training and live extraction. |
| `sld` | Inspection of the raw CSVs shows this is actually the second-level-domain **label text** (e.g. `"microsoft"`, `"local"`, `"dvg-gestalt"`), not a numeric feature at all. Excluded as non-numeric. |
| `longest_word` | Inspection shows this is the longest **dictionary word** found by an offline NLP word-segmentation pass over the domain (values like `"microsoft"`, `"local"`, `"C"`), not a length. Reproducing it live would require bundling a word-segmentation dictionary for no clear detection benefit; `labels_max` (longest DNS *label* by character count) already captures the comparable structural signal and is fully live-observable. |

Per the project's standing rule, **unavailable or ambiguous features are
marked and excluded, never fabricated.**

## Stateful features — excluded from the trained classifier

`stateful_features-*.csv` contains window-level DNS behaviour: per-record-type
frequencies (`A_frequency`, `TXT_frequency`, ...), `rr_count`,
`rr_name_entropy`, `rr_name_length`, `ttl_mean`, `ttl_variance`, and several
columns serialized as Python set/dict/list literals: `distinct_ns`,
`distinct_ip`, `unique_country`, `unique_asn`, `distinct_domains`,
`reverse_dns`, `unique_ttl`.

This phase does **not** train a second supervised model on this file,
because:

1. **No row-level join key.** The stateful CSV has no timestamp or flow
   identifier that aligns its rows with the stateless CSV's per-query rows,
   so the two cannot be joined for a single labeled training table without
   guessing at an alignment.
2. **Several columns are not live-observable without external services.**
   `unique_country` and `unique_asn` require GeoIP/ASN lookups this project
   does not perform; `reverse_dns` requires historical PTR resolution state.
   Fabricating these live would violate the "do not invent missing
   features" requirement.

Instead, window-level behaviour is captured **live**, directly, by
`dns_features.DNSWindowTracker`: it aggregates the *per-query classifier's
own verdicts* (not the dataset's stateful columns) over a sliding window per
source IP, and only raises a detection when a sustained fraction of recent
queries from that source look like tunneling. This satisfies the "sliding
DNS analysis window" / "low-and-slow" requirement using only genuinely
live-observable signal, clearly documented as a heuristic corroboration
layer rather than a second trained model.

## Canonical `DetectionResult` mapping

Both the Random Forest (DoS/PortScan) and the DNS tunneling model report
through the same shape (see `app.py`'s `publish_live_alert` /
`publish_dns_alert`):

```
attack_type, label, confidence, model_name, model_version,
source_ip, destination_ip, timestamp, feature_values, explanation,
detection_method
```

`detection_method` is always set to the real model name (e.g. `"CICIDS-2017
Random Forest + Scapy"` or `"DNS feature pipeline + dns_tunnel_rf"`) so the
UI never mislabels which model produced a given verdict.

## Extending this

To retrain on the full "heavy" dataset: drop the additional
`Attacks/stateless_features-heavy_*.csv` and `Benign/stateless_features-*.csv`
files into `dataset/dns/Attacks/` and `dataset/dns/Benign/` respectively (same
column schema) and re-run `python ml/train_dns_model.py` — it globs every
`stateless_features-*.csv` file under the configured data directory.
