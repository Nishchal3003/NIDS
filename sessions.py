"""Role-based session registry.

Backs the three application roles (CLIENT, ATTACKER, MONITOR) required by
the role-separated front end. This is the backend source of truth for
"who is allowed to do what" -- the frontend hiding a button is never
sufficient on its own (see app.py's /api/attack/* route guards).

Design notes:
  * client_id / attacker_id are generated server-side (CLIENT-0001,
    ATTACKER-0001, ...) and are never derived from the username the
    person typed in. A username never becomes a trusted identity.
  * One login (browser session, via Flask's signed session cookie) keeps
    the same client_id/attacker_id across reconnects; each Socket.IO
    connection gets its own session_id (the Socket.IO sid).
  * In-memory only, consistent with the rest of the project.
"""
import threading
import time

CLIENT, ATTACKER, MONITOR = "client", "attacker", "monitor"


class SessionRegistry:
    def __init__(self):
        self.lock = threading.Lock()
        self._client_seq = 0
        self._attacker_seq = 0
        self.logins = {}  # login_token (Flask session id) -> {client_id, role, username}
        self.sockets = {}  # socket sid -> session dict (role, client_id, username, source_ip, connected_at, status)

    # -- HTTP login (issues a stable client_id/attacker_id for the browser session) --
    def login_client(self, login_token, username):
        with self.lock:
            existing = self.logins.get(login_token)
            if existing and existing["role"] == CLIENT:
                existing["username"] = username
                return existing
            self._client_seq += 1
            record = {
                "client_id": f"CLIENT-{self._client_seq:04d}",
                "role": CLIENT,
                "username": username,
            }
            self.logins[login_token] = record
            return record

    def login_attacker(self, login_token, username):
        with self.lock:
            existing = self.logins.get(login_token)
            if existing and existing["role"] == ATTACKER:
                return existing
            self._attacker_seq += 1
            record = {
                "client_id": f"ATTACKER-{self._attacker_seq:04d}",
                "role": ATTACKER,
                # The typed username is kept only as an operator label -- it is
                # never treated as a normal client identity (see module docstring).
                "username": username,
                "display_name": "AUTHORIZED SECURITY TEST",
            }
            self.logins[login_token] = record
            return record

    def login_for(self, login_token):
        with self.lock:
            return dict(self.logins[login_token]) if login_token in self.logins else None

    # -- Socket.IO connection registry (one entry per live connection) --
    def register_socket(self, sid, login_record, source_ip):
        now = time.time()
        with self.lock:
            session = {
                "client_id": login_record["client_id"],
                "role": login_record["role"],
                "username": login_record["username"],
                "display_name": login_record.get("display_name", login_record["username"]),
                "session_id": sid,
                "source_ip": source_ip,
                "connected_at": now,
                "status": "ACTIVE",
            }
            self.sockets[sid] = session
            return dict(session)

    def unregister_socket(self, sid):
        with self.lock:
            session = self.sockets.pop(sid, None)
            return dict(session) if session else None

    def get(self, sid):
        with self.lock:
            session = self.sockets.get(sid)
            return dict(session) if session else None

    def is_attacker(self, sid):
        with self.lock:
            session = self.sockets.get(sid)
            return bool(session and session["role"] == ATTACKER)

    def role_for_login_token(self, login_token):
        record = self.login_for(login_token)
        return record["role"] if record else None

    def list_by_role(self, role):
        with self.lock:
            return [dict(s) for s in self.sockets.values() if s["role"] == role]

    def list_all(self):
        with self.lock:
            return [dict(s) for s in self.sockets.values()]

    def snapshot(self):
        with self.lock:
            sockets = list(self.sockets.values())
        return {
            "total_sessions": len(sockets),
            "clients": [s for s in sockets if s["role"] == CLIENT],
            "attackers": [s for s in sockets if s["role"] == ATTACKER],
        }
