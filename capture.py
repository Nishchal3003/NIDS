"""Scapy/Npcap live packet capture and CICIDS flow scoring."""
import os
import platform
import threading
import time
from collections import defaultdict, deque

try:
    from scapy.all import (
        AsyncSniffer,
        IP,
        IPv6,
        TCP,
        UDP,
        conf,
        get_if_addr,
        get_if_list,
    )
except Exception:
    AsyncSniffer = IP = IPv6 = TCP = UDP = conf = get_if_addr = get_if_list = None


class LivePacketCapture:
    def __init__(self, detector, on_alert, interface=None):
        self.detector = detector
        self.on_alert = on_alert
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
        self.lock = threading.Lock()

    @staticmethod
    def _new_flow():
        return {"first": 0.0, "last": 0.0, "bytes": 0, "fwd": 0, "bwd": 0,
                "syn": 0, "rst": 0}

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
        if self.status == "running":
            self.status = "stopped"

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
            key = (source, destination, source_port, destination_port, proto)
            now = time.time()
            with self.lock:
                self.packet_count += 1
                self.capture_history.append(now)
                flow = self.flows[key]
                flow["first"] = flow["first"] or now
                flow["last"] = now
                flow["bytes"] += len(packet)
                flow["fwd"] += 1
                if packet.haslayer(TCP):
                    flags = int(packet[TCP].flags)
                    flow["syn"] += int(bool(flags & 0x02))
                    flow["rst"] += int(bool(flags & 0x04))
                duration = max(now - flow["first"], 0.001)
                features = {
                    "destination_port": destination_port,
                    "flow_duration_us": duration * 1_000_000,
                    "total_fwd_packets": flow["fwd"],
                    "total_bwd_packets": flow["bwd"],
                    "flow_bytes_per_s": flow["bytes"] / duration,
                    "flow_packets_per_s": flow["fwd"] / duration,
                    "syn_flag_count": flow["syn"],
                    "rst_flag_count": flow["rst"],
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
