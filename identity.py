"""Identity/Session context.

Correlates a raw network flow's source IP with the application-level
client/session identity the Flask-SocketIO relay already tracks (display
name, session id, connect time). This is a read-only enrichment layer: it
never gates or alters detection, it only answers "who is this" when known,
so alerts and risk scoring can show a name instead of a bare IP.
"""
import threading
import time
from collections import deque


class IdentityRegistry:
    def __init__(self, history=500):
        self.lock = threading.Lock()
        self.by_ip = {}  # ip -> {name, sid, connected_at, last_seen, session_count}
        self.event_log = deque(maxlen=history)

    def register(self, ip, sid, name, ts=None):
        if not ip:
            return
        ts = ts if ts is not None else time.time()
        with self.lock:
            entry = self.by_ip.get(ip)
            if entry is None:
                entry = {"connected_at": ts, "session_count": 0}
                self.by_ip[ip] = entry
            if entry.get("sid") != sid:
                entry["session_count"] = entry.get("session_count", 0) + 1
            entry["sid"] = sid
            entry["name"] = name
            entry["last_seen"] = ts
            entry.pop("disconnected_at", None)
            self.event_log.append({"ts": ts, "ip": ip, "sid": sid, "name": name})

    def touch(self, ip, ts=None):
        if not ip:
            return
        with self.lock:
            entry = self.by_ip.get(ip)
            if entry:
                entry["last_seen"] = ts if ts is not None else time.time()

    def disconnect(self, ip, sid, ts=None):
        if not ip:
            return
        ts = ts if ts is not None else time.time()
        with self.lock:
            entry = self.by_ip.get(ip)
            if entry and entry.get("sid") == sid:
                entry["disconnected_at"] = ts

    def context_for(self, ip):
        with self.lock:
            entry = self.by_ip.get(ip)
            return dict(entry) if entry else None

    def is_known(self, ip):
        with self.lock:
            entry = self.by_ip.get(ip)
            return bool(entry and entry.get("disconnected_at") is None)

    def snapshot(self, limit=100):
        with self.lock:
            sources = [
                {"ip": ip, **data} for ip, data in list(self.by_ip.items())[:limit]
            ]
        sources.sort(key=lambda s: s.get("last_seen", 0), reverse=True)
        return {"known_sources": len(self.by_ip), "sources": sources}
