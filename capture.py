"""Scapy/Npcap live packet capture and CICIDS flow scoring."""
import os
import platform
import statistics
import threading
import time
from collections import defaultdict, deque

try:
    from scapy.all import (
        AsyncSniffer,
        DNS,
        DNSQR,
        IP,
        IPv6,
        TCP,
        UDP,
        conf,
        get_if_addr,
        get_if_list,
    )
except Exception:
    AsyncSniffer = DNS = DNSQR = IP = IPv6 = TCP = UDP = conf = get_if_addr = get_if_list = None

try:
    from dns_features import extract_stateless as _extract_dns_features, DNSWindowTracker
except Exception:
    _extract_dns_features = None
    DNSWindowTracker = None


class LivePacketCapture:
    def __init__(
        self,
        detector,
        on_alert,
        interface=None,
        on_metrics=None,
        metrics_interval=1.0,
        recon_engine=None,
        on_recon=None,
        identity_lookup=None,
        dns_detector=None,
        on_dns_alert=None,
        dns_window_seconds=60.0,
    ):
        self.detector = detector
        self.on_alert = on_alert
        self.on_metrics = on_metrics  # optional: called once per metrics_interval with an ambient-traffic summary
        self.metrics_interval = metrics_interval
        self.recon_engine = recon_engine  # optional ReconEngine: multi-window scan detection (recon.py)
        self.on_recon = on_recon  # optional callback for new ReconEngine findings
        self.identity_lookup = identity_lookup  # optional callable(ip) -> identity context dict or None
        # Independent DNS tunneling pipeline (dns_features.py / dns_detector.py).
        # Entirely separate from the CICIDS flow classifier above -- a DNS
        # verdict never touches self.detector or vice versa.
        self.dns_detector = dns_detector
        self.on_dns_alert = on_dns_alert
        self.dns_window = DNSWindowTracker(window_seconds=dns_window_seconds) if DNSWindowTracker else None
        self.dns_last_alert = {}
        self.interface = interface or os.getenv("NIDS_CAPTURE_INTERFACE") or None
        self.packet_filter = os.getenv(
            "NIDS_CAPTURE_FILTER", "ip and (tcp or udp)"
        )
        self.enabled = os.getenv("NIDS_CAPTURE_ENABLED", "1").lower() not in {"0", "false", "no"}
        self.status = "disabled" if not self.enabled else "not started"
        self.backend = "unavailable"
        self.packet_count = 0
        self.callback_errors = 0
        self.last_error = None
        self.sniffer = None
        self.flows = defaultdict(self._new_flow)
        self.scan_ports = defaultdict(deque)
        self.syn_windows = defaultdict(deque)
        self.last_alert = {}
        self.capture_history = deque(maxlen=300)
        # Bounded ambient-traffic event log, used only to build baseline metrics
        # windows (see _metrics_loop). Independent of self.flows / detection.
        self.metric_events = deque(maxlen=8000)
        self.lock = threading.Lock()
        self._metrics_stop = threading.Event()
        self._metrics_thread = None

    @staticmethod
    def _new_flow():
        return {
            "first": 0.0,
            "last": 0.0,
            "bytes": 0,
            "fwd": 0,
            "bwd": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "syn": 0,
            "rst": 0,
            "ack": 0,
            "fin": 0,
            "packet_lengths": deque(maxlen=512),
            "fwd_lengths": deque(maxlen=512),
            "bwd_lengths": deque(maxlen=512),
            "iat": deque(maxlen=512),
            "fwd_iat": deque(maxlen=512),
            "bwd_iat": deque(maxlen=512),
            "last_direction": {},
        }

    def start(self):
        if not self.enabled:
            self.status = "disabled by NIDS_CAPTURE_ENABLED"
            return False
        if AsyncSniffer is None:
            self.status = "unavailable: install scapy and Npcap"
            return False
        try:
            if platform.system() == "Windows":
                # Npcap exposes WinPcap-compatible devices through libpcap.
                conf.use_pcap = True
                self.backend = "Npcap/libpcap"
            else:
                self.backend = "libpcap/Scapy"
            self.interface = self.interface or str(conf.iface)
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._packet,
                store=False,
            )
            self.sniffer.start()
            self.status = "running"
            if self.on_metrics is not None:
                self._metrics_stop.clear()
                self._metrics_thread = threading.Thread(
                    target=self._metrics_loop, daemon=True
                )
                self._metrics_thread.start()
            return True
        except Exception as exc:
            self.status = f"unavailable: {type(exc).__name__}: {exc}"
            self.sniffer = None
            return False

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self._metrics_stop.set()
        if self.status == "running":
            self.status = "stopped"

    def _metrics_loop(self):
        """Every metrics_interval seconds, summarize ambient traffic and hand
        it to the baseline callback. Runs independently of attack detection
        and of any authorized packet-test window."""
        while not self._metrics_stop.wait(self.metrics_interval):
            now = time.time()
            window_start = now - self.metrics_interval
            with self.lock:
                events = [e for e in self.metric_events if e[0] >= window_start]
            if not events:
                metrics = {
                    "packets_per_s": 0.0,
                    "bytes_per_s": 0.0,
                    "unique_sources": 0,
                    "unique_dest_ports": 0,
                    "syn_ratio": 0.0,
                }
            else:
                total = len(events)
                total_bytes = sum(e[1] for e in events)
                syn_count = sum(1 for e in events if e[3])
                metrics = {
                    "packets_per_s": total / self.metrics_interval,
                    "bytes_per_s": total_bytes / self.metrics_interval,
                    "unique_sources": len({e[2] for e in events}),
                    "unique_dest_ports": len({e[4] for e in events}),
                    "syn_ratio": syn_count / total,
                }
            try:
                self.on_metrics(metrics)
            except Exception as exc:
                with self.lock:
                    self.last_error = f"metrics callback: {type(exc).__name__}: {exc}"

    def reset_detection_state(self):
        """Discard pre-test flow evidence so ambient traffic cannot trigger a test alert."""
        with self.lock:
            self.flows.clear()
            self.scan_ports.clear()
            self.syn_windows.clear()
            self.last_alert.clear()

    def _packet(self, packet):
        try:
            if IP is None:
                return
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None:
                return
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip.proto)
            source = str(getattr(ip, "src", ""))
            destination = str(getattr(ip, "dst", ""))
            source_port = int(getattr(transport, "sport", 0) or 0)
            destination_port = int(getattr(transport, "dport", 0) or 0)
            endpoint = (source, source_port)
            reverse_endpoint = (destination, destination_port)
            ordered_endpoints = (
                (endpoint, reverse_endpoint)
                if endpoint <= reverse_endpoint
                else (reverse_endpoint, endpoint)
            )
            key = ordered_endpoints + (proto,)
            now = time.time()
            with self.lock:
                self.packet_count += 1
                self.capture_history.append(now)
                is_syn = bool(packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02)
                self.metric_events.append((now, len(packet), source, is_syn, destination_port))
                flow = self.flows[key]
                flow["first"] = flow["first"] or now
                previous = flow["last"]
                flow["last"] = now
                packet_length = len(packet)
                flow["bytes"] += packet_length
                flow["packet_lengths"].append(packet_length)
                if previous:
                    flow["iat"].append(now - previous)
                direction = "fwd" if endpoint == key[0] else "bwd"
                flow[direction] += 1
                flow[f"{direction}_bytes"] += packet_length
                prior_direction = flow["last_direction"].get(direction)
                if prior_direction is not None:
                    flow[f"{direction}_iat"].append(now - prior_direction)
                flow["last_direction"][direction] = now
                flow[f"{direction}_lengths"].append(packet_length)
                if packet.haslayer(TCP):
                    flags = int(packet[TCP].flags)
                    flow["syn"] += int(bool(flags & 0x02))
                    flow["rst"] += int(bool(flags & 0x04))
                    flow["ack"] += int(bool(flags & 0x10))
                    flow["fin"] += int(bool(flags & 0x01))
                duration = max(now - flow["first"], 0.001)
                lengths = list(flow["packet_lengths"])
                iats = list(flow["iat"])
                fwd_iats = list(flow["fwd_iat"])
                bwd_iats = list(flow["bwd_iat"])
                mean_length = statistics.fmean(lengths) if lengths else 0.0
                features = {
                    "destination_port": destination_port,
                    "flow_duration_us": duration * 1_000_000,
                    "total_fwd_packets": flow["fwd"],
                    "total_bwd_packets": flow["bwd"],
                    "total_length_of_fwd_packets": flow["fwd_bytes"],
                    "total_length_of_bwd_packets": flow["bwd_bytes"],
                    "flow_bytes_per_s": flow["bytes"] / duration,
                    "flow_packets_per_s": (flow["fwd"] + flow["bwd"]) / duration,
                    "fwd_packets_per_s": flow["fwd"] / duration,
                    "bwd_packets_per_s": flow["bwd"] / duration,
                    "flow_iat_mean": statistics.fmean(iats) * 1_000_000 if iats else 0.0,
                    "flow_iat_std": statistics.pstdev(iats) * 1_000_000 if len(iats) > 1 else 0.0,
                    "flow_iat_max": max(iats, default=0.0) * 1_000_000,
                    "flow_iat_min": min(iats, default=0.0) * 1_000_000,
                    "fwd_iat_total": sum(fwd_iats) * 1_000_000,
                    "fwd_iat_mean": statistics.fmean(fwd_iats) * 1_000_000 if fwd_iats else 0.0,
                    "bwd_iat_total": sum(bwd_iats) * 1_000_000,
                    "bwd_iat_mean": statistics.fmean(bwd_iats) * 1_000_000 if bwd_iats else 0.0,
                    "min_packet_length": min(lengths, default=0),
                    "max_packet_length": max(lengths, default=0),
                    "packet_length_mean": mean_length,
                    "packet_length_std": statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
                    "average_packet_size": mean_length,
                    "down_up_ratio": flow["bwd"] / max(flow["fwd"], 1),
                    "syn_flag_count": flow["syn"],
                    "rst_flag_count": flow["rst"],
                    "ack_flag_count": flow["ack"],
                    "fin_flag_count": flow["fin"],
                }
                ports = self.scan_ports[source]
                ports.append((now, destination_port))
                while ports and now - ports[0][0] > 5:
                    ports.popleft()
                distinct_ports = sorted({port for _, port in ports if port})
                syn_window = self.syn_windows[source]
                if packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02:
                    syn_window.append(now)
                while syn_window and now - syn_window[0] > 1:
                    syn_window.popleft()
                source_syn_count = len(syn_window)
            if self.recon_engine is not None:
                recon_finding = self.recon_engine.observe(source, destination_port, ts=now)
                if recon_finding and self.on_recon:
                    try:
                        self.on_recon(recon_finding)
                    except Exception as exc:
                        with self.lock:
                            self.callback_errors += 1
                            self.last_error = f"recon callback: {type(exc).__name__}: {exc}"
            self._handle_dns(packet, source, now)
            label, probability, shap_values = self.detector.classify_live(
                features,
                distinct_ports=len(distinct_ports),
                source_syn_count=source_syn_count,
            )
            if label not in {"DoS", "PortScan"} or probability < 0.85:
                return
            alert_key = (source, label)
            if now - self.last_alert.get(alert_key, 0) < 10:
                return
            self.last_alert[alert_key] = now
            identity = self.identity_lookup(source) if self.identity_lookup else None
            self.on_alert({
            "ts": now,
            "source": source,
            "source_ip": source,
            "destination": destination,
            "destination_ip": destination,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": proto,
            "threat_type": label,
            "severity": "CRITICAL" if label == "DoS" else "HIGH",
            "detection_method": "CICIDS-2017 Random Forest + Scapy",
            "traffic_source": "Npcap raw packet capture",
            "prediction": label,
            "confidence": round(probability * 100, 1),
            "identity": identity,
            "features": {
                **features,
                "unique_destination_ports": len(distinct_ports),
                "window_seconds": 5,
            },
            "shap": shap_values,
            "observed_rule": (
                f"Live flow classified as {label}; "
                f"{len(distinct_ports)} distinct destination ports observed in 5 seconds."
            ),
            })
        except Exception as exc:
            with self.lock:
                self.callback_errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"

    def _handle_dns(self, packet, source, now):
        """Independent DNS tunneling path: a DNS query packet never touches
        self.detector (the CICIDS flow model) and a DNS verdict never
        touches self.flows. Entirely separate model, separate alert."""
        if DNS is None or self.dns_detector is None or self.dns_window is None:
            return
        if not packet.haslayer(DNS) or packet[DNS].qr != 0 or not packet.haslayer(DNSQR):
            return
        try:
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            fqdn = qname.rstrip(".")
            if not fqdn:
                return
            features = _extract_dns_features(fqdn)
            label, confidence, shap_values = self.dns_detector.classify(features)
            is_suspicious = label == "DNS_TUNNELING"
            window = self.dns_window.observe(source, fqdn, is_suspicious, confidence, ts=now)
            if not window["window_flag"] or self.on_dns_alert is None:
                return
            if now - self.dns_last_alert.get(source, 0) < 20:
                return
            self.dns_last_alert[source] = now
            identity = self.identity_lookup(source) if self.identity_lookup else None
            self.on_dns_alert({
                "ts": now,
                "source": source,
                "source_ip": source,
                "fqdn": fqdn,
                "threat_type": "DNS_TUNNELING",
                "detection_method": f"DNS feature pipeline + {self.dns_detector.metadata.get('model_name', 'dns_tunnel_rf')}",
                "traffic_source": "Npcap raw packet capture (DNS)",
                "confidence": round(confidence, 1),
                "identity": identity,
                "features": features,
                "shap": shap_values,
                "window": window,
                "observed_rule": (
                    f"{window['window_suspicious']}/{window['window_total']} DNS queries from this "
                    f"source in the last {self.dns_window.window_seconds:.0f}s classified as tunneling."
                ),
            })
        except Exception as exc:
            with self.lock:
                self.callback_errors += 1
                self.last_error = f"dns callback: {type(exc).__name__}: {exc}"

    def diagnostics(self):
        interfaces = []
        if get_if_list is not None:
            for name in get_if_list():
                try:
                    address = get_if_addr(name)
                except Exception:
                    address = None
                interfaces.append({"name": str(name), "address": address})
        return {
            "platform": platform.system(),
            "backend": self.backend,
            "status": self.status,
            "interface": self.interface,
            "filter": self.packet_filter,
            "packet_count": self.packet_count,
            "callback_errors": self.callback_errors,
            "last_error": self.last_error,
            "flow_count": len(self.flows),
            "scan_sources": {
                source: len({port for _, port in events if port})
                for source, events in self.scan_ports.items()
            },
            "interfaces": interfaces,
        }
