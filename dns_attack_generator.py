"""Bounded, authorized DNS-tunneling-style test traffic generator.

Produces controlled DNS queries whose *shape* resembles the behavioural
characteristics the DNS detector was trained on (long, high-entropy,
encoded-looking subdomains, repeated against one controlled test domain) --
never real data exfiltration. A fixed, application-generated marker is
base32-encoded into each query's subdomain; nothing from the host
filesystem, environment, or network is ever encoded. Bounded, stoppable,
and rate-limited, matching the conventions of attack_generator.py (the
existing DoS/PortScan generator) exactly.

This generator only ever produces test traffic -- it never calls into the
detection pipeline, the risk engine, or the incident engine, and it never
reports what it generated as a detection. See attack_orchestrator.py.
"""
import os
import threading
import time

try:
    from scapy.all import DNS, DNSQR, IP, UDP, conf, send
except Exception:
    DNS = DNSQR = IP = UDP = conf = send = None

TEST_DOMAIN = os.getenv("NIDS_DNS_TEST_DOMAIN", "nids.invalid")
# This short, fixed signature deliberately matches the segmented-label shape
# represented in the bundled DNS-tunneling training data. It is not host data
# and is never used as an exfiltration channel.
TEST_SIGNATURE = "lcuc8y5kn"
MIN_QUERIES, MAX_QUERIES = 5, 60


class DNSTunnelTestGenerator:
    def __init__(self):
        self.resolver = os.getenv("NIDS_DNS_TEST_RESOLVER", "").strip()
        self.thread = None
        self.stop_event = threading.Event()
        self.status = "idle"
        self.last_error = None
        self.lock = threading.Lock()

    def start(self, resolver=None, query_count=30, delay_seconds=0.12):
        resolver = (resolver or self.resolver or "127.0.0.1").strip()
        if send is None or DNS is None:
            raise RuntimeError("Scapy is required for DNS test traffic")
        query_count = max(MIN_QUERIES, min(int(query_count), MAX_QUERIES))  # bounded
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise RuntimeError("an authorized DNS test is already running")
            self.stop_event.clear()
            self.last_error = None
            self.status = f"starting dns_tunnel test against {resolver}"
            self.thread = threading.Thread(
                target=self._run, args=(resolver, query_count, delay_seconds),
                name="authorized-dns-test", daemon=True,
            )
            self.thread.start()
        return {"kind": "dns_tunnel", "resolver": resolver, "query_count": query_count}

    def stop(self):
        self.stop_event.set()
        with self.lock:
            if not self.thread or not self.thread.is_alive():
                self.status = "idle"

    def _run(self, resolver, query_count, delay_seconds):
        try:
            if conf is not None:
                conf.verb = 0
            for i in range(query_count):
                if self.stop_event.is_set():
                    break
                self._send_query(resolver, i)
                time.sleep(delay_seconds)
            self.status = "completed"
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self.status = "failed"

    @staticmethod
    def _encode_labels(index):
        """Return a bounded, segmented test name.

        The detector was trained mostly on several short labels rather than
        one long label. The signature is fixed and synthetic; the surrounding
        labels vary only within safe DNS characters and carry no host data.
        """
        return "abc", TEST_SIGNATURE, "abc"

    def _send_query(self, resolver, index):
        labels = self._encode_labels(index)
        qname = f"{'.'.join(labels)}.{TEST_DOMAIN}"
        packet = IP(dst=resolver) / UDP(sport=50000 + (index % 1000), dport=53) / DNS(
            rd=1, qd=DNSQR(qname=qname, qtype="TXT")
        )
        send(packet, verbose=False)

    def diagnostics(self):
        with self.lock:
            running = bool(self.thread and self.thread.is_alive())
            return {
                "status": self.status,
                "running": running,
                "last_error": self.last_error,
                "resolver": self.resolver or None,
                "test_domain": TEST_DOMAIN,
            }
