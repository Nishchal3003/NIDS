# XAI-NIDS-Live Project Guide

## 1. Project purpose

XAI-NIDS-Live is a self-contained LAN communication system with an explainable
live network detector. Browser clients and terminal clients communicate through
one Flask-SocketIO server. Attack validation generates bounded packets only for
an explicitly supplied private-LAN target; the detector never consumes attack
events or labels from Socket.IO.

The project keeps communication and detection state in memory only. At startup the
detector trains one three-class Random Forest from the bundled CICIDS-2017
DoS, PortScan, and BENIGN flow rows (bounded samples, never once per packet).
When Scapy and Windows Npcap are available, a second pipeline aggregates live
IP/TCP/UDP flows and scores them with that same model. Alerts remain available only while
the server process and dashboard session are running; no chat, packet-test, or
detection history is written to a database or other persistent store.

## 2. Important scope

The project observes application messages for communication and raw IP/TCP/UDP
flows for security detection. Chat and file events are not attack features.

The monitor can show:

- Event name
- Source client name
- Short connection/session ID
- Event category
- Payload size
- Socket.IO transport label
- Direction
- Accepted or blocked state
- Source client display name and IP address
- Request rate and rolling traffic history
- Bounded, authorized private-LAN SYN/DoS and PortScan packet tests
- A selectable Attack Explanation Panel backed by the selected real alert

Raw IP addresses, TCP flags, source ports, destination ports, Ethernet headers,
and wire-level protocol fields require a capture backend such as Scapy/Npcap,
appropriate operating-system permissions, and a separate capture integration.

## 3. Project files

| File | Responsibility |
| --- | --- |
| `app.py` | Flask routes, Socket.IO room, client state, live alert publication, PDF report |
| `explanation.py` | Evidence-backed structured explanations for DoS and port-scan alerts |
| `detector.py` | CICIDS-2017 training, shared flow features, prediction, optional SHAP attribution |
| `capture.py` | Optional Scapy/Npcap flow aggregation and live model scoring |
| `terminal_client.py` | Interactive terminal room client with chat, files, and authorized packet tests |
| `attack_generator.py` | Private-LAN-only bounded Scapy packet generation |
| `templates/client.html` | Responsive browser communication client |
| `templates/monitor.html` | Live operations dashboard, chart, alerts, packet stream, report button |
| `requirements.txt` | Python dependencies |
| `README.md` | Short project overview and quick-start instructions |
| `PROJECT_GUIDE.md` | Full architecture, commands, behavior, endpoints, and limitations |

## 4. Requirements

- Windows, macOS, or Linux
- Python 3.10+
- A network connection for devices that will communicate over LAN
- Python packages listed in `requirements.txt`

Install dependencies. Npcap is an operating-system prerequisite for live
capture on Windows; install it from the official Nmap distribution with
**WinPcap API-compatible mode** enabled:

```powershell
cd C:\Users\dell\Desktop\nids-live
python -m pip install -r requirements.txt
```

The server still starts if Scapy, Npcap, or capture privileges are unavailable;
the `/health` response reports the reason. Attack tests require Scapy, Npcap,
and suitable privileges.
When Npcap is active, `/health` reports `capture.backend` as
`Npcap/libpcap`, the selected NPF device, the BPF filter, discovered interfaces,
and the number of packets received.

## 5. Start the server

From the project directory:

```powershell
python app.py
```

The server listens on all interfaces at port `5000`.

Local URLs:

```text
http://127.0.0.1:5000/
http://127.0.0.1:5000/monitor
http://127.0.0.1:5000/health
```

Find the Windows LAN address:

```powershell
ipconfig
```

Look for the active Wi-Fi or Ethernet adapter's IPv4 address, for example
`192.168.1.25`. Other devices on the same network can then use:

```text
http://192.168.1.25:5000/
http://192.168.1.25:5000/monitor
```

If another device cannot connect, check the Windows firewall and allow inbound
TCP traffic for port `5000`.

## 6. Browser client

Open `/` in one or more browser tabs.

Features:

- Set a display name
- See the live room roster
- Send chat messages
- Press Enter to send
- Share files from the browser
- See connection state
- Start bounded authorized packet tests for a private-LAN target
- Receive system and IDS notifications

All chat and file activity is broadcast to connected clients. Files are kept in
memory and are not saved by the server.

## 7. Terminal client

Open a second PowerShell window:

```powershell
cd C:\Users\dell\Desktop\nids-live
python terminal_client.py http://127.0.0.1:5000 terminal-user
```

For a different machine on the same LAN:

```powershell
python terminal_client.py http://192.168.1.25:5000 laptop-user
```

Normal text is sent to the room:

```text
hello from the terminal
```

Available commands:

```text
/help
/name NEW_NAME
/file C:\path\to\file.txt
/dos
/scan
/stop
/quit
```

Command behavior:

- `/help` prints the command list.
- `/name NEW_NAME` changes the room display name.
- `/file PATH` reads and shares a file up to 15 MB.
- `/dos` sends a bounded five-second SYN test to TCP port 80 on the configured
  RFC1918 target.
- `/scan` sends SYN probes to a bounded fixed port list on the configured
  RFC1918 target.
- `/stop` requests that the packet test stop.
- `/quit` disconnects.

Packet generation uses a stoppable background thread and bounded duration.

The browser buttons are explicitly named **Send DoS attack** and **Send
PortScan attack**. Their monitor ledger entries are marked `blocked` and
include the initiating client's display name and IP address. Normal chat and
file events remain `accepted`.

## 8. Detection flow

1. An authorized packet test sends bounded TCP SYN packets to a private-LAN target.
2. Npcap captures the resulting raw packets independently of the command/event.
3. Scapy aggregates packets by five-tuple and tracks source-level port diversity.
4. The CICIDS-2017-trained Random Forest predicts BENIGN, DoS, or PortScan. Training
   happens once at process startup from the CSV files in `dataset/`.
5. Live classification applies the model plus source-level behavioural evidence:
   eight distinct destination ports within five seconds for PortScan, and
   sustained high-rate SYN traffic for DoS.
6. SHAP attribution, threat assessment, and dashboard publication happen only
   after captured-flow classification during an explicitly authorized packet-test
   window started by `/dos`, `/scan`, or one of the browser buttons. Ambient
   traffic is never promoted to an attack alert.
7. An authorized DoS test is reported as DoS, and an authorized PortScan test
   is reported as PortScan; the two test labels are not mixed.
8. The monitor displays the selected report in the Attack Explanation Panel,
   including evidence, rule-vs-ML provenance, and available SHAP attribution.

Detector features:

- `destination_port`
- `flow_duration_us`
- `total_fwd_packets`
- `total_bwd_packets`
- `flow_bytes_per_s`
- `flow_packets_per_s`
- `syn_flag_count`
- `rst_flag_count`

For live capture, Scapy aggregates packets by five-tuple and derives these
CICIDS-compatible fields. Source-level distinct-port tracking supplies the
additional evidence needed to distinguish a live port scan from one flow.
The explicit client buttons start packet generation; they do not send attack
events or features to the detector.

### Live capture configuration

Live capture is enabled by default and degrades safely when unavailable:

```powershell
$env:NIDS_CAPTURE_ENABLED = "1"
$env:NIDS_CAPTURE_INTERFACE = "\Device\NPF_{YOUR-NPCAP-ADAPTER-GUID}"
$env:NIDS_CAPTURE_FILTER = "ip and (tcp or udp)"
$env:NIDS_ATTACK_TARGET = "192.168.0.50" # optional; active private IPv4 is auto-selected
$env:NIDS_TRAIN_ROWS_PER_CLASS = "10000"
# Optional comma-separated CSV paths:
$env:NIDS_DATA_FILES = "dataset\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv,dataset\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
python app.py
```

To list Npcap interfaces and their IP addresses:

```powershell
python -c "from scapy.all import get_if_list, get_if_addr; [print(i, get_if_addr(i)) for i in get_if_list()]"
```

Use the NPF device corresponding to the active adapter, and run the console
with sufficient capture privileges. If `NIDS_ATTACK_TARGET` is omitted, the
active private IPv4 interface address is selected automatically. The browser
and terminal buttons then need no IP input. Check `/health` for model
training rows/files, Npcap backend status, selected interface, filter, packet
count, and the configured attack target.
Set `NIDS_CAPTURE_ENABLED` to `0` only when capture should be intentionally
disabled.

## 9. Monitor dashboard

Open:

```text
http://127.0.0.1:5000/monitor
```

The monitor contains:

- Traffic pulse chart
- Requests-per-second counter
- Connected-client counter
- Session alert counter
- Detection engine summary
- Explainable anomaly cards for DoS and port scans
- Interactive Attack Explanation Panel populated only from real alerts
- SHAP feature attribution bars
- Raw feature details
- Live application packet stream (and live capture status via `/health`)
- Accepted/blocked packet state, with attack rows showing name and IP
- PDF report download button
- Evaluate Model button with asynchronous progress and final metrics

The monitor graph is attack-only. It remains flat during normal chat and file
communication and spikes only when a captured attack alert is published.
Normal application traffic remains visible in the packet stream and counters.

To demonstrate the complete path:

1. Keep `/monitor` open.
2. Connect a browser or terminal client.
3. Enter an RFC1918 target that you own or are authorized to test.
4. Use the bounded packet-test button or `/dos TARGET` / `/scan TARGET`.
5. Confirm `/health` shows Npcap packets increasing and inspect the alert origin.
6. Press `/stop` if the client has not been automatically stopped.

## 10. API endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Browser communication client |
| `/monitor` | GET | Live security dashboard |
| `/health` | GET | Server status, client count, request rate, packet rate |
| `/api/alerts` | GET | Current in-memory anomaly report history |
| `/api/packets` | GET | In-memory packet metadata ledger |
| `/api/packet_summary` | GET | Packet categories observed during the last 30 seconds |
| `/api/health_series` | GET | Thirty one-second traffic buckets |
| `/api/evaluate_model` | GET/POST | Start an asynchronous model evaluation |
| `/api/evaluate_model/status` | GET | Read evaluation status and completed metrics |
| `/api/report.pdf` | GET | Downloadable multi-page PDF security report |

PowerShell examples:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
Invoke-RestMethod http://127.0.0.1:5000/api/packets
Invoke-RestMethod http://127.0.0.1:5000/api/packet_summary
Invoke-WebRequest http://127.0.0.1:5000/api/report.pdf -OutFile nids-live-report.pdf
```

## 11. PDF report

The monitor's **Download PDF** button calls `/api/report.pdf`.

The report is generated from the current in-memory state and includes:

- Branded report header and page numbering
- Generation timestamp
- Executive summary
- Packet count for the last 30 seconds
- Captured DoS and PortScan alert counts
- Alert count
- Chat, file, DoS attack, PortScan attack, and control event mix
- Client display names and source IP addresses
- Accepted/blocked status for packet-ledger entries
- Readable 30-second attack-only graph; it remains flat without attacks
- Recent detections, exact labels, confidence values, and mitigation state
- Detector feature description
- Packet ledger with time, source, event, kind, bytes, and state
- Scope and raw-packet limitation

The report is generated without an extra PDF package and is not written to
disk by the server. Use the browser download or save the response manually.

## 12. Model evaluation

The **Evaluate Model** button starts `/api/evaluate_model` in a background
thread. This prevents the browser from remaining stuck on one long synchronous
request while the bundled CICIDS rows are evaluated. The page polls
`/api/evaluate_model/status` until the job is `complete` or `failed`, then
shows accuracy, precision, recall, and F1 in the Detection Engine card.

Evaluation output is written by the detector to the existing `results/`
directory (`evaluation.json`, `classification_report.txt`, and
`confusion_matrix.png`). Chat, packet, and alert session state remains
in-memory only.

## 13. Validation commands

Compile the Python modules:

```powershell
python -m py_compile app.py detector.py terminal_client.py
```

Start the server:

```powershell
python app.py
```

Check the server:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```

Check PDF output:

```powershell
Invoke-WebRequest http://127.0.0.1:5000/api/report.pdf -OutFile report.pdf
```

Start and inspect model evaluation:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:5000/api/evaluate_model
Invoke-RestMethod http://127.0.0.1:5000/api/evaluate_model/status
```

## 14. Data lifetime and safety

- State is held in process memory.
- Restarting the server clears clients, chat, files, packet counters, and
  alert history.
- Packet and alert histories are bounded deques.
- File messages are limited by the Socket.IO buffer and terminal client limit.
- Packet tests are bounded and restricted to RFC1918 private-LAN targets.
- Do not run packet tests against systems you do not own or operate.

## 15. Troubleshooting

### Terminal cannot connect

Confirm that `python app.py` is running, the URL includes port `5000`, and the
Windows firewall allows the server. Use `127.0.0.1` on the same computer and
the server's LAN IPv4 address from another computer.

### Packet test does not appear

Keep the terminal process running after `/dos TARGET` or `/scan TARGET`,
confirm the monitor is connected, and use `/stop` before restarting a test.
Check that Npcap packet counters increase; chat/file traffic alone cannot
produce an attack alert.

### PDF is empty

The PDF always includes the report structure and chart. Packet and alert
sections will say that no events were recorded if the server has not observed
traffic yet. Generate traffic first, then download again.

### Evaluate Model remains on “Evaluating…”

Evaluation runs asynchronously. Check
`http://127.0.0.1:5000/api/evaluate_model/status` directly. A `failed` result
includes the error; confirm the dataset files and dependencies from
`requirements.txt` are available. A page refresh does not cancel a running
server-side evaluation.

### Live capture is unavailable

Run `Invoke-RestMethod http://127.0.0.1:5000/health` and inspect
`capture.status`. Install Scapy and Npcap, select the correct interface, and
run with capture privileges. Setting `NIDS_CAPTURE_ENABLED=0` intentionally
disables it. Application-level communication does not produce attack alerts.
