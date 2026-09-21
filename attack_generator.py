"""Bounded, authorized private-LAN packet generation for local validation."""
import ipaddress
import os
import socket
import threading
import time

try:
    from scapy.all import IP, TCP, conf, get_if_addr, get_if_list, send
except Exception:
    IP = TCP = conf = get_if_addr = get_if_list = send = None


class AuthorizedAttackGenerator:
    def __init__(self):
        self.target = os.getenv("NIDS_ATTACK_TARGET", "").strip()
        if not self.target:
            self.target = self._discover_private_target()
        self.thread = None
        self.stop_event = threading.Event()
        self.status = "idle"
        self.last_error = None
        self.lock = threading.Lock()
        if self.target:
            self.target = self._validate_target(self.target)

    @staticmethod
    def _discover_private_target():
        if get_if_addr is None:
            return ""
        interfaces = [conf.iface] if conf is not None else []
        if get_if_list is not None:
            interfaces.extend(get_if_list())
        for interface in interfaces:
            try:
                candidate = get_if_addr(interface)
            except Exception:
                continue
            try:
                return AuthorizedAttackGenerator._validate_target(candidate)
            except (TypeError, ValueError):
                continue
        return ""

    def configure_from_interface(self, interface):
        if self.target:
            return
        if get_if_addr is None:
            return
        try:
            candidate = self._validate_target(get_if_addr(interface))
        except (TypeError, ValueError):
            candidate = ""
        if candidate:
            self.target = candidate

    def configure_from_address(self, address):
        if self.target:
            return
        try:
            self.target = self._validate_target(address)
        except (TypeError, ValueError):
            return

    @staticmethod
    def _validate_target(target):
        address = ipaddress.ip_address(str(target).strip())
        if not address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("target must be an RFC1918 private-LAN IPv4 address")
        if address.version != 4:
            raise ValueError("target must be an IPv4 address")
        return str(address)

    @staticmethod
    def _validate_ports(ports):
        values = sorted({int(port) for port in ports})
        if not values or len(values) > 32 or any(port < 1 or port > 65535 for port in values):
            raise ValueError("ports must contain 1-32 valid TCP ports")
        return values

    def start(self, kind, target=None, ports=None):
        target = self._validate_target(target or self.target)
        if send is None:
            raise RuntimeError("Scapy is required for packet generation")
        if kind not in {"portscan", "syn_dos"}:
            raise ValueError("unsupported packet test")
        validated_ports = self._validate_ports(ports or [80]) if kind == "portscan" else []
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise RuntimeError("an authorized packet test is already running")
            self.stop_event.clear()
            self.last_error = None
            self.status = f"starting {kind} against {target}"
            args = (kind, target, validated_ports)
            self.thread = threading.Thread(
                target=self._run, args=args, name="authorized-packet-test", daemon=True
            )
            self.thread.start()
        return {"kind": kind, "target": target, "ports": args[2]}

    def stop(self):
        self.stop_event.set()
        with self.lock:
            if not self.thread or not self.thread.is_alive():
                self.status = "idle"

    def _run(self, kind, target, ports):
        try:
            interface = os.getenv("NIDS_CAPTURE_INTERFACE") or None
            local_address = ""
            if interface and get_if_addr is not None:
                try:
                    local_address = str(get_if_addr(interface))
                except Exception:
                    local_address = ""
            if kind == "portscan":
                for index, port in enumerate(ports):
                    if self.stop_event.is_set():
                        break
                    self._probe_tcp(target, port, local_address)
                    time.sleep(0.15)
            elif kind == "syn_dos":
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and not self.stop_event.is_set():
                    self._probe_tcp(target, 80, local_address)
                    time.sleep(0.02)
            else:
                raise ValueError("unsupported packet test")
            self.status = "completed"
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self.status = "failed"

    @staticmethod
    def _probe_tcp(target, port, local_address=""):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(0.08)
        try:
            if local_address:
                connection.bind((local_address, 0))
            connection.connect_ex((target, port))
        finally:
            connection.close()

    def diagnostics(self):
        with self.lock:
            running = bool(self.thread and self.thread.is_alive())
            return {
                "status": self.status,
                "running": running,
                "last_error": self.last_error,
                "target": self.target or None,
            }
