# NIDS-Live — Intelligent Network Intrusion Detection System

> **Real packet capture · Dual ML models · SHAP explanations · Role-separated UI · DNS Tunneling detection**

An end-to-end security demonstration platform built on a **CLIENT / ATTACKER / MONITOR** role model. The system captures live packets, runs two independent machine learning pipelines (CICIDS-2017 Random Forest for DoS/PortScan, CIC-Bell-DNS-EXF-2021 Random Forest for DNS tunneling), generates SHAP-backed SOC explanations, scores risk, manages incidents, and broadcasts role-appropriate alerts in real time over WebSockets.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Detection Pipeline](#2-detection-pipeline)
3. [Dual ML Models](#3-dual-ml-models)
4. [Role System](#4-role-system)
5. [Attack Orchestration](#5-attack-orchestration)
6. [API Reference](#6-api-reference)
7. [Socket.IO Events](#7-socketio-events)
8. [Configuration](#8-configuration)
9. [Project Structure](#9-project-structure)
10. [Quick Start](#10-quick-start)
11. [Testing](#11-testing)
12. [End-to-End Demo](#12-end-to-end-demo)
13. [Troubleshooting](#13-troubleshooting)
14. [Known Limitations](#14-known-limitations)

---

## 1. System Architecture

```
NORMAL USERS                    AUTHORIZED ATTACKER          SECURITY MONITOR
     |                                  |                           |
     v                                  v                           v
/client/login               /attacker/login                    /monitor
     |                                  |                    (no login needed)
     v                                  v                           ^
   /client  <--- Socket.IO room --->  /attacker                     |
                                                                     |
                  Flask-SocketIO backend (app.py)                    |
                                                                     |
                LAUNCH ATTACK (single button)                        |
                        |                                            |
            attack_orchestrator.py                                   |
            secrets.choice(DOS | PORTSCAN | DNS_TUNNEL)              |
                        |                                            |
            bounded generator starts real packets                    |
                        |                                            |
                capture.py  (Scapy / Npcap)                         |
                        |                                            |
                flow aggregation -> feature extraction               |
                        |                                            |
                +------------------+   +------------------+         |
                | CICIDS-2017 RF   |   | CIC-Bell-DNS RF  |         |
                | DoS / PortScan   |   |  DNS Tunneling   |         |
                +--------+---------+   +--------+---------+         |
                         +-----------+-----------+                   |
                     SHAP explanation (explanation.py)               |
                                  |                                  |
                         Risk scoring (risk.py)                      |
                                  |                                  |
                       Incident engine (incidents.py)                |
                                  |                                  |
                +-------------------+-------------------+            |
                v                                       v            |
         security_alert                     anomaly / incident ------+
         (non-technical, clients room)       (full payload, monitor)
```

> **Key design principle:** The orchestrator **never** tells the detector which attack was launched. The capture -> features -> ML -> risk pipeline makes that determination entirely independently. Attack type is only revealed *after* the detector reports a result, for audit/demo correlation only.

---

## 2. Detection Pipeline

| Stage | Module | Description |
|---|---|---|
| **Capture** | `capture.py` | Scapy/Npcap live packet capture; gracefully degrades if no raw socket access |
| **Flow features** | `detector.py` | Extracts CICIDS-2017-compatible per-flow features (packet rates, byte counts, flag ratios, inter-arrival times) |
| **DNS features** | `dns_features.py` | Per-query stateless features (entropy, subdomain length, label counts, character ratios) in a sliding window |
| **CICIDS ML** | `detector.py` `AnomalyDetector` | Trained Random Forest — DoS / PortScan / BENIGN |
| **DNS ML** | `dns_detector.py` `DNSTunnelDetector` | Trained Random Forest — DNS_TUNNELING / BENIGN |
| **Behavioural** | `recon.py` `ReconEngine` | Deterministic port-scan counter (no ML) |
| **Baseline** | `baseline.py` | Adaptive traffic baseline; flags drift from session-normal behaviour |
| **Explanation** | `explanation.py` | Builds a structured SOC evidence pack: severity, evidence bullets, SHAP contributions, recommended action |
| **Risk** | `risk.py` | Multi-signal risk score combining ML confidence, source history, and behavioural indicators |
| **Identity** | `identity.py` | Correlates source IP -> session identity for human-readable attribution |
| **Incidents** | `incidents.py` | Creates, updates, and resolves incident records with full timeline |

---

## 3. Dual ML Models

### Model 1 — CICIDS-2017 Random Forest (`models/random_forest.pkl`)

| Property | Value |
|---|---|
| **Training dataset** | CICIDS-2017 (Friday DDoS + PortScan CSVs) |
| **Algorithm** | `sklearn` Random Forest Classifier |
| **Classes** | `BENIGN`, `DoS`, `PortScan` |
| **Explainability** | SHAP `TreeExplainer` |
| **Feature source** | Live flow aggregation via Scapy |

### Model 2 — DNS Tunnel Detector (`models/dns_tunnel_rf.pkl`)

| Property | Value |
|---|---|
| **Training dataset** | CIC-Bell-DNS-EXF-2021 (stateless per-query features, light subset) |
| **Algorithm** | `sklearn` Random Forest Classifier |
| **Classes** | `BENIGN`, `DNS_TUNNELING` |
| **Training rows** | 102,774 (82,219 train / 20,555 test) |
| **Macro F1** | 0.77 |
| **DNS_TUNNELING recall** | ~99.9% |
| **BENIGN recall** | ~60.9% |
| **Features (11)** | `subdomain_length`, `upper`, `lower`, `numeric`, `special`, `entropy`, `labels`, `labels_max`, `labels_average`, `len`, `subdomain` |
| **Explainability** | SHAP `TreeExplainer` |

To retrain the DNS model:

```bash
python ml/train_dns_model.py
```

This reads `dataset/dns/{Attacks,Benign}/stateless_features-*.csv`, writes `models/dns_tunnel_rf.pkl` + `models/dns_tunnel_rf.metadata.json`, and prints a full precision/recall/F1/confusion-matrix report.

See [`dns/FEATURE_MAPPING.md`](dns/FEATURE_MAPPING.md) for the full dataset -> live-packet -> model feature mapping and known exclusions.

---

## 4. Role System

| Role | Login URL | Identity Format | Capabilities |
|---|---|---|---|
| **CLIENT** | `/client/login` | `CLIENT-0001`, `CLIENT-0002`, ... | Private chat, file sharing, security status alerts |
| **ATTACKER** | `/attacker/login` | `ATTACKER-0001` (displayed as `AUTHORIZED SECURITY TEST`) | All client features + **LAUNCH ATTACK** button |
| **MONITOR** | `/monitor` | None (no login) | Full technical dashboard: source IP, confidence %, SHAP values, risk score, incident timeline |

**Identity is server-side only.** A user who types "Alice" at the attacker login is still issued `ATTACKER-0001` and displayed as `AUTHORIZED SECURITY TEST`. Role enforcement is applied independently on both the Socket.IO handlers and REST endpoints — hiding a button is not access control.

```
POST /api/attack/dos  (as a normal client session)
-> 403  {"error": "Security testing controls are restricted to the authorized attacker role."}
```

---

## 5. Attack Orchestration

The attacker has a single **LAUNCH ATTACK** button. The backend randomly selects one of three attack types using `secrets.choice`:

```
LAUNCH ATTACK
    |
    v
attack_orchestrator.py
secrets.choice([DOS, PORTSCAN, DNS_TUNNEL])
    |
    +-- DOS        -> AuthorizedAttackGenerator  (RFC1918-only SYN flood)
    +-- PORTSCAN   -> AuthorizedAttackGenerator  (bounded port sweep)
    +-- DNS_TUNNEL -> DNSTunnelTestGenerator     (~30 queries, ~3.6s burst)
    |
    v
Real packets on the monitored interface
    |
    v
Independent detection pipeline runs
    |
    v
orchestrator.note_detection()  <- correlates result back (audit only)
    |
    v
attack_test_completed -> MATCH / MISS + which attack was actually launched
```

The attacker never knows which type was launched until the detector independently reports a result. The correlation is **audit-only** and never feeds back into the detection logic.

---

## 6. API Reference

### Health & Observability

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | Service health |
| `GET` | `/ready` | Readiness probe (ML models loaded?) |
| `GET` | `/live` | Liveness probe |
| `GET` | `/metrics` | Prometheus-style text metrics |

### Core Dashboard APIs

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/alerts` | Recent anomaly alert history |
| `GET` | `/api/baseline` | Current traffic baseline state |
| `GET` | `/api/recon` | Active reconnaissance findings |
| `GET` | `/api/risk` | Current risk scores by source |
| `GET` | `/api/identity` | Source IP -> session identity map |
| `GET` | `/api/incidents` | All incidents (list) |
| `GET` | `/api/incidents/<id>` | Single incident with full timeline |
| `GET` | `/api/report.pdf` | PDF report of current session |

### Attack Control (role-gated — 403 for non-attackers)

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/attack/dos` | Start bounded DoS test (direct) |
| `POST` | `/api/attack/portscan` | Start bounded PortScan test (direct) |
| `POST` | `/api/v1/attack/launch` | Random orchestrated attack launch |
| `GET` | `/api/v1/attack/status/<test_run_id>` | Status of a specific test run |
| `GET` | `/api/v1/attack/history` | All test run records |

### V1 Read-Only Aliases (diagnostics / scripting)

`/api/v1/system/status` · `/api/v1/clients` · `/api/v1/sessions` · `/api/v1/incidents` · `/api/v1/alerts` · `/api/v1/risk` · `/api/v1/recon` · `/api/v1/baseline` · `/api/v1/metrics` · `/api/v1/model`

### Safe Diagnostics (never trigger a detection)

`GET /api/v1/test/connectivity` · `GET /test/ml` · `GET /test/capture` · `GET /test/socket` · `POST /test/demo`

---

## 7. Socket.IO Events

| Event | Direction | Description |
|---|---|---|
| `connect` / `disconnect` | client <-> server | Register/remove session, join `clients` or `attackers` room |
| `set_name` | client -> server | Set display name |
| `chat_message` | both | Private chat relay |
| `file_message` | both | File relay (base64, max 20 MB) |
| `launch_attack` | attacker -> server | Trigger random orchestrated attack |
| `start_packet_test` / `stop_packet_test` | attacker -> server | Role-gated direct packet test |
| `packet_test_status` | server -> attacker | Test start confirmation |
| `attack_test_requested` | server -> attacker | Orchestrator acknowledged |
| `attack_test_started` | server -> attacker | Generator started (type hidden) |
| `attack_test_completed` | server -> attacker | Type revealed + MATCH/MISS |
| `security_alert` | server -> clients room | Non-technical alert ("channel under attack") |
| `monitor_activation` | server -> clients room | Opens `/monitor` in a new tab |
| `security_incident_detected` | server -> all | Full incident payload |
| `anomaly` | server -> all | Full technical alert payload (monitor dashboard) |
| `detection_result` | server -> all | ML pipeline result |
| `risk_updated` | server -> all | Risk score changed |
| `incident_created` | server -> all | New incident opened |
| `baseline_drift` | server -> all | Traffic baseline drift detected |
| `recon_finding` | server -> all | New reconnaissance indicator |
| `incident_update` | server -> all | Incident status changed |

---

## 8. Configuration

Copy `.env.example` to `.env` and adjust. All variables are optional for local demo use.

```env
# Flask session signing
NIDS_SECRET_KEY=nids-live-demo

# Packet capture
NIDS_CAPTURE_INTERFACE=
NIDS_CAPTURE_FILTER=ip and (tcp or udp)
NIDS_CAPTURE_ENABLED=1

# DoS/PortScan attack target (RFC1918 auto-discovery if blank)
NIDS_ATTACK_TARGET=

# DNS tunneling test
NIDS_DNS_TEST_DOMAIN=nids-test.invalid
NIDS_DNS_TEST_RESOLVER=

# Random attack orchestration
ATTACK_AUTOMATION_ENABLED=1
ATTACK_COOLDOWN_SECONDS=10
ALLOWED_ATTACK_TYPES=DOS,PORTSCAN,DNS_TUNNEL
ATTACK_CORRELATION_TIMEOUT_SECONDS=30
```

---

## 9. Project Structure

```
NIDS-full/
+-- app.py                        # Flask + Flask-SocketIO main application
+-- detector.py                   # CICIDS-2017 Random Forest + feature extraction
+-- dns_detector.py               # CIC-Bell-DNS-EXF-2021 DNS tunnel RF detector
+-- dns_features.py               # Per-query stateless DNS feature extractor
+-- dns_attack_generator.py       # Bounded DNS tunnel query burst generator
+-- attack_generator.py           # Bounded DoS / PortScan generator
+-- attack_orchestrator.py        # Random 3-way attack orchestration
+-- capture.py                    # Scapy / Npcap live packet capture
+-- baseline.py                   # Adaptive traffic baseline + drift detection
+-- recon.py                      # Multi-window reconnaissance engine
+-- identity.py                   # Source IP -> session identity registry
+-- risk.py                       # Multi-signal risk scorer
+-- incidents.py                  # Incident lifecycle manager
+-- sessions.py                   # Role / session registry (CLIENT / ATTACKER)
+-- explanation.py                # SOC explanation builder (SHAP + evidence)
+-- terminal_client.py            # CLI test client
|
+-- templates/
|   +-- role_select.html          # Landing page
|   +-- client.html               # Client chat + security status
|   +-- client_login.html
|   +-- attacker.html             # Attacker lab (LAUNCH ATTACK + chat)
|   +-- attacker_login.html
|   +-- monitor.html              # Live security dashboard (technical)
|   +-- incidents.html            # Incident list
|   +-- incident_detail.html      # Single incident timeline + acknowledge/resolve
|
+-- models/
|   +-- random_forest.pkl         # Trained CICIDS-2017 model
|   +-- dns_tunnel_rf.pkl         # Trained DNS tunnel model
|   +-- dns_tunnel_rf.metadata.json
|
+-- dataset/
|   +-- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
|   +-- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
|   +-- dns/
|       +-- Attacks/              # CIC-Bell-DNS-EXF-2021 tunneling CSVs (6 types)
|       +-- Benign/               # CIC-Bell-DNS-EXF-2021 benign traffic CSV
|
+-- ml/
|   +-- train_dns_model.py        # DNS model training script
|
+-- dns/
|   +-- FEATURE_MAPPING.md        # Dataset -> live feature mapping + exclusions
|
+-- results/
|   +-- evaluation.json
|   +-- classification_report.txt
|   +-- confusion_matrix.png
|
+-- tests/                        # 12 pytest modules
+-- requirements.txt
+-- .env.example
```

---

## 10. Quick Start

### Prerequisites

- Python 3.9+
- [Npcap](https://npcap.com/) (Windows) or `CAP_NET_RAW` (Linux/macOS) for live capture *(optional — app runs without it)*

### Install & Run

```bash
git clone https://github.com/Nishchal3003/NIDS.git
cd NIDS
pip install -r requirements.txt
cp .env.example .env   # optional
python app.py
```

Open `http://localhost:5000/` in your browser.

### Retrain DNS model (optional)

```bash
python ml/train_dns_model.py
```

---

## 11. Testing

| Test file | Coverage |
|---|---|
| `test_detector.py` | CICIDS anomaly detector |
| `test_baseline.py` | Adaptive traffic baseline |
| `test_recon.py` | Reconnaissance engine |
| `test_identity.py` | Identity registry |
| `test_risk.py` | Risk scorer |
| `test_incidents.py` | Incident lifecycle |
| `test_sessions.py` | Role / session registry |
| `test_dns_features.py` | DNS per-query feature extractor |
| `test_dns_detector.py` | DNS tunnel detector |
| `test_attack_orchestrator.py` | Random orchestration, cooldown, MATCH/MISS |
| `test_random_attack_integration.py` | Full chain: orchestrator -> generator -> detection |
| `test_roles_integration.py` | Login -> role enforcement -> alerts -> monitor activation |

```bash
python -m pytest tests/ -v
```

---

## 12. End-to-End Demo

```bash
python app.py
```

1. Open `http://localhost:5000/` — choose a role.
2. **Browser 1** — Client Login — `Alice`.
3. **Browser 2** — Client Login — `Bob`.
4. **Browser 3** (private window) — Attacker Lab — any name.
5. Click **LAUNCH ATTACK** on the attacker page.
6. The orchestrator secretly picks DoS, PortScan, or DNS Tunneling.
7. Within seconds:
   - Alice and Bob see a **SECURITY ALERT** overlay.
   - `/monitor` opens in a new tab (source IP, confidence, SHAP, risk).
   - The attacker page reveals which attack was launched and the MATCH/MISS result.
8. Visit `/incidents` — open the incident — view timeline — Acknowledge — Resolve.

---

## 13. Troubleshooting

| Symptom | Fix |
|---|---|
| **No LAN target found** | Connect a second device on the same network, or set `NIDS_ATTACK_TARGET` in `.env`. The system falls back to a local authorized-test path. |
| **`403` on `/api/attack/*`** | Visit `/attacker/login` first — the attacker role is required. |
| **Capture shows `unavailable`** | Install Npcap (Windows) or run with `CAP_NET_RAW` (Linux/macOS). |
| **DNS tunnel not detected** | Set `NIDS_DNS_TEST_RESOLVER` — queries need a reachable resolver for Npcap to observe them. |
| **DNS model not found** | Run `python ml/train_dns_model.py`. The CICIDS model is bundled. |

---

## 14. Known Limitations

- **In-memory state only** — sessions, alerts, and incidents reset on restart. No database persistence.
- **DNS BENIGN recall (~61%)** — trained on the bundled "light" CIC-Bell-DNS-EXF-2021 subset (~103k rows, 11 features). Some benign DNS traffic may be misclassified during a test window. Retraining on the full dataset would improve this.
- **Window-level DNS detection is heuristic** — sliding majority-ratio over per-query verdicts, not a second trained classifier.
- **No cross-dataset evaluation** — UNSW-NB15 / CSE-CIC-IDS2018 adapters and a canonical feature-schema layer are a substantial separate effort.
- **DNS query burst assumes a reachable resolver** — in a completely isolated sandbox the generator thread may fail silently (reflected in its own `status`/`last_error`).

---

## Dependencies

| Package | Purpose |
|---|---|
| `flask` | Web framework |
| `flask-socketio` | WebSocket server |
| `python-socketio` | Socket.IO protocol |
| `scikit-learn` | Random Forest classifiers |
| `shap` | Model explainability (TreeExplainer) |
| `numpy` | Numerical operations |
| `pandas` | DataFrame handling for DNS features |
| `scapy` | Live packet capture and crafting |
| `matplotlib` | Confusion matrix plots |

---

*For deep internals of each module, see [`PROJECT_GUIDE.md`](PROJECT_GUIDE.md).*
