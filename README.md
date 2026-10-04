# NIDS-Live — Role-Separated Intelligent Network Intrusion Detection System

An end-to-end demonstration platform: real packet capture, a CICIDS-2017
Random Forest, SHAP explanations, adaptive baseline/drift detection,
multi-window reconnaissance, identity correlation, risk scoring, and an
incident lifecycle — now wrapped in a proper **CLIENT / ATTACKER / MONITOR**
role model instead of a single shared demo page.

For the original, pre-role-separation architecture and every core module's
internals, see `PROJECT_GUIDE.md`. This document covers what changed and how
to run the new end-to-end demo.

## 1. Architecture

```
NORMAL USERS                         AUTHORIZED ATTACKER
     |                                       |
     v                                       v
/client/login  ---------------------  /attacker/login
     |                                       |
     v                                       v
   /client                               /attacker
     |                                       |
     +-------------- private communication --+
                          |
                 (same Flask-SocketIO backend)
                          |
                          v
              AUTHORIZED SECURITY TEST
              (bounded attack generator)
                          |
                          v
            REAL PACKETS on the monitored interface
                          |
                          v
        Scapy/Npcap capture -> flow aggregation -> features
                          |
                          v
       Random Forest -> behavioural/recon/baseline detectors
                          |
                          v
                   SHAP explanation
                          |
                          v
                    Risk correlation
                          |
                          v
                    Incident engine
                          |
              +-----------+-----------+
              v                       v
      security_alert (clients)   full incident (monitor)
              |                       |
              v                       v
     "channel under attack"    /monitor auto-activates
```

The attack generator **starts a real, bounded test**. It never tells the
backend "DoS detected" — the NIDS pipeline (capture → flow → features →
Random Forest → risk → incident) makes that determination independently,
exactly as before this change. See `app.py::_run_attack_test` and
`publish_live_alert`.

## 2. Roles

| Role | Identity | Sees |
|---|---|---|
| **CLIENT** | `CLIENT-0001`, `CLIENT-0002`, ... | Private chat, participant roster, security status. **Never** attack controls. |
| **ATTACKER** | `ATTACKER-0001`, ... (display: `AUTHORIZED SECURITY TEST`) | Same chat channel + a Security Test Lab (DoS/PortScan test buttons). |
| **MONITOR** | n/a (no login) | `/monitor` — full technical detail: source IP, confidence, SHAP, risk, incident timeline. |

Identity is issued server-side (`sessions.py`) and is never derived from the
username typed at login — an attacker who types "Alice" is still recorded
and displayed as `ATTACKER-000N` / `AUTHORIZED SECURITY TEST`, never as a
trusted client identity.

## 3. Login workflow

1. `GET /` — role-selection landing page.
2. `POST /client/login` (username only, no password — this is a controlled
   demo environment, not production auth) → issues `CLIENT-000N`, redirects
   to `/client`.
3. `POST /attacker/login` (username only, kept only as a display label) →
   issues `ATTACKER-000N`, redirects to `/attacker`.
4. Both use Flask's signed session cookie to remember the role/identity
   across requests and Socket.IO reconnects.

## 4. Communication workflow

`/client` and `/attacker` both connect to the same Socket.IO backend and
share the `chat_message`/`file_message` events — private communication is
unchanged from before this sprint. `/client` shows **only** communication +
security status. `/attacker` additionally shows the Security Test Lab.

## 5. Attack-testing workflow

1. Attacker clicks **Send DoS Test** / **Send PortScan Test** on `/attacker`
   (or `POST /api/attack/dos` / `/api/attack/portscan`).
2. Backend checks the caller's session role is `ATTACKER` — **403** otherwise
   (see Security model below).
3. `AuthorizedAttackGenerator` starts bounded, RFC1918-only traffic.
4. Scapy/Npcap captures the resulting packets independently.
5. The existing detection pipeline runs unchanged (flow → features → RF →
   SHAP → risk → incident).

## 6. Automatic detection & notification workflow

`publish_live_alert` (unchanged detection logic, new broadcast logic):

- Emits `anomaly` (full technical payload) — unchanged, monitor already
  listens for this.
- Emits `security_alert` to the `clients` Socket.IO room only — a short,
  non-technical message ("this channel is under attack"), no SHAP/RF/
  confidence detail.
- Emits `monitor_activation` to the `clients` room with `{"redirect":
  "/monitor"}` — the client page auto-navigates there ~7 seconds after
  showing the alert (no popup windows, since browsers block those).
- Emits `security_incident_detected` (full payload: incident id, severity,
  category, source/destination IP, risk, confidence, timeline) to everyone.

## 7. API architecture

Existing routes (`/api/alerts`, `/api/baseline`, `/api/recon`, `/api/risk`,
`/api/identity`, `/api/incidents`, `/api/report.pdf`, etc.) are unchanged.
New in this sprint:

- `GET /ready`, `GET /live`, `GET /metrics`
- `GET /api/incidents/<id>` (single incident, was previously list-only)
- `POST /api/attack/dos`, `POST /api/attack/portscan` — role-gated (403 for
  non-attackers)
- `GET /api/v1/system/status`, `/api/v1/clients`, `/api/v1/sessions`,
  `/api/v1/incidents`, `/api/v1/alerts`, `/api/v1/risk`, `/api/v1/recon`,
  `/api/v1/baseline`, `/api/v1/metrics`, `/api/v1/model` — thin, read-only
  aliases over the routes above, for diagnostics/scripting
- `GET /api/v1/test/connectivity`, `/test/ml`, `/test/capture`, `/test/socket`,
  `POST /test/demo` — safe diagnostics; none of them trigger or fake a
  detection

## 8. Socket.IO event architecture

| Event | Direction | Purpose |
|---|---|---|
| `connect` / `disconnect` | client ↔ server | Registers/removes the session in `sessions.py`, joins the `clients` or `attackers` room |
| `set_name`, `chat_message`, `file_message` | both | Unchanged private communication |
| `start_packet_test`, `stop_packet_test` | attacker → server | Role-gated; server replies with `packet_test_status` |
| `security_alert` | server → clients room | Client-safe attack notice |
| `monitor_activation` | server → clients room | Tells the client page to auto-redirect to `/monitor` |
| `security_incident_detected` | server → all | Full technical incident payload |
| `anomaly` | server → all | Original full alert payload (monitor dashboard) |
| `baseline_drift`, `recon_finding`, `incident_update` | server → all | Unchanged from the previous sprint |

## 9. Security model

Hiding a button is not access control. Both the Socket.IO handler
(`on_start_packet_test`) and the REST endpoints (`/api/attack/dos`,
`/api/attack/portscan`) independently verify, **server-side**, that the
caller's session role is `ATTACKER` before starting any test:

```
POST /api/attack/dos   (as a normal client)
403
{"error": "Security testing controls are restricted to the authorized attacker role."}
```

A username is never sufficient to become the attacker role — only
`/attacker/login` issues it.

## 10. Testing

- `tests/test_sessions.py` — role/session registry unit tests
- `tests/test_roles_integration.py` — full chain: client login → attacker
  login → role enforcement on both the socket and REST attack paths →
  confirmed detection → incident creation → client-safe broadcast →
  monitor activation payload, plus health/ready/live/metrics and every
  `/api/v1/*` route
- All previously existing tests (detector, baseline, recon, identity, risk,
  incidents) are unmodified and still pass

Run everything: `python -m pytest tests/ -v`

## 11. End-to-end demonstration

```
python app.py
```

1. Open `http://localhost:5000/` → role selection.
2. In one browser: Client Login → `Alice`.
3. In another browser (or private window): Client Login → `Bob`.
4. In a third: Security Test / Attacker Lab → any name.
5. On the attacker page, click **Send PortScan Test** (or DoS).
6. Within seconds, Alice and Bob each see a **SECURITY ALERT** overlay, then
   auto-navigate to `/monitor`.
7. `/monitor` shows the detected attack (source IP, confidence, risk).
8. Visit `/incidents` → open the incident → see the timeline and evidence →
   Acknowledge → Resolve.

## 12. Troubleshooting

- **No LAN target found** — the attack generator needs a private-LAN target;
  open a client from another device on the same network, or set
  `NIDS_ATTACK_TARGET`. Locally, the system falls back to a same-host
  authorized test telemetry path so the detection pipeline can still be
  demonstrated (see `_publish_local_attack_test`).
- **`403` on `/api/attack/*`** — you're not logged in as the attacker role in
  this browser session; visit `/attacker/login` first.
- **Capture shows `unavailable`** — live packet capture needs Npcap
  (Windows) or root/`CAP_NET_RAW` (Linux/macOS); the app still runs and
  serves every page without it.

## 13. Randomized three-attack testing (DoS / PortScan / DNS Tunneling)

The attacker page now has exactly one control, **LAUNCH ATTACK**. The
backend (`attack_orchestrator.py`) randomly selects one of `DOS`,
`PORTSCAN`, or `DNS_TUNNEL` via `secrets.choice`, starts that bounded
generator, and never tells the attacker — or the detector — which one it
picked. The type is only revealed once the independent detection pipeline
reports a result (`attack_test_completed`), alongside whether it matched
(`MATCH`/`MISS`).

```
LAUNCH ATTACK -> orchestrator picks 1 of 3 -> bounded generator starts
     -> real packets -> capture.py -> correct detector -> result
     -> orchestrator.note_detection() correlates it back onto the test run
        (audit only -- this never influences the detection already made)
```

**DNS tunneling detection is a second, independent model** — not the
CICIDS-2017 Random Forest. See `dns/FEATURE_MAPPING.md` for the full
dataset → live-packet → model feature mapping (CIC-Bell-DNS-EXF-2021,
stateless per-query features only; several dataset columns were found on
inspection to be non-numeric or ambiguous and are explicitly excluded,
never guessed at). A sliding per-source window (`dns_features.py`) smooths
individual query verdicts so slow/low-rate tunneling is judged on
sustained behaviour, not one query.

Train/retrain the DNS model:
```
python ml/train_dns_model.py
```
This reads `dataset/dns/{Attacks,Benign}/stateless_features-*.csv`, writes
`models/dns_tunnel_rf.pkl` + `.metadata.json`, and prints precision/recall/
F1/confusion-matrix. Current bundled-data result: macro F1 ≈ 0.77 (DNS_TUNNELING
recall ≈ 0.999, BENIGN recall ≈ 0.61 — see §14 limitations).

New config (see `.env.example`): `ATTACK_AUTOMATION_ENABLED`,
`ATTACK_COOLDOWN_SECONDS`, `ALLOWED_ATTACK_TYPES`,
`ATTACK_CORRELATION_TIMEOUT_SECONDS`, `NIDS_DNS_TEST_DOMAIN`,
`NIDS_DNS_TEST_RESOLVER`.

New routes/events: `POST /api/v1/attack/launch` (role-gated, 403 for
non-attackers), `GET /api/v1/attack/status/<test_run_id>`,
`GET /api/v1/attack/history`; Socket.IO `launch_attack` (in),
`attack_test_requested` / `attack_test_started` / `attack_test_completed`
(out), plus `detection_result`, `risk_updated`, `incident_created` emitted
alongside the existing `anomaly`/`security_alert`/`monitor_activation`.

**Monitor now opens in a new tab**, never replacing the client page — see
`templates/client.html`'s `monitor_activation` handler (`window.open` with
a named target so repeat attacks focus the same tab; a visible "Open
Security Monitor" button appears if the browser blocks the popup).

## 14. Known limitations of this sprint

- Session/role/incident state is in-memory only (consistent with the rest
  of the project) and resets on restart.
- The monitor dashboard's detection-pipeline checklist and animated timeline
  view described in the original request were scoped down to the existing
  alert/risk/incident cards plus the `/incident/<id>` timeline page, to keep
  this change reviewable; a fuller visual timeline on `/monitor` itself is a
  reasonable follow-up.
- The startup splash/init-sequence animation was not built; `/health`,
  `/ready`, and the console output already report the same information.
- The vestigial, never-triggered `run_packet_test` browser-side fetch code
  in the old combined page was dropped as dead code during the rewrite.
- **DNS model quality**: trained only on the bundled "light" CIC-Bell-DNS-EXF-2021
  subset (~103k rows) with 11 honestly-reproducible features; BENIGN recall
  (~61%) is noticeably weaker than DNS_TUNNELING recall (~99.9%), meaning
  some ordinary DNS traffic will be misclassified as tunneling during a
  test window. Retraining on the full "heavy" dataset (see
  `dns/FEATURE_MAPPING.md` §"Extending this") would likely improve this;
  not done here to keep the bundled dataset size reasonable.
- **No stateful/window-level model**: window-level DNS behaviour is a live
  heuristic (sliding majority-ratio over per-query verdicts), not a second
  trained classifier — the dataset's stateful CSV has no row-level join key
  to the stateless CSV and several of its columns aren't live-observable
  (see `dns/FEATURE_MAPPING.md`).
- **Cross-dataset evaluation (UNSW-NB15 / CSE-CIC-IDS2018) and the canonical
  feature-schema adapter layer were not built this phase** — this is a
  substantial separate effort (dataset adapters, a canonical schema,
  compatible-subset evaluation, honest same-dataset-vs-cross-dataset
  reporting) and is called out here explicitly rather than attempted
  partially.
- The DNS test generator's bounded query burst (~30 queries, ~3.6s) assumes
  a reachable resolver IP on the wire for Npcap to observe; with no
  reachable private-LAN target it will still send the packets (capture does
  not require a reply), but a completely isolated sandbox with no
  configured network interface may see the generator thread fail silently
  (reflected in its own `status`/`last_error`, not a crash).
