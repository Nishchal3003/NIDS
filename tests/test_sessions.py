from sessions import SessionRegistry, CLIENT, ATTACKER


def test_client_login_assigns_sequential_ids_not_username():
    registry = SessionRegistry()
    alice = registry.login_client("tok-1", "Alice")
    bob = registry.login_client("tok-2", "Bob")
    assert alice["client_id"] == "CLIENT-0001"
    assert bob["client_id"] == "CLIENT-0002"
    assert alice["role"] == CLIENT


def test_attacker_login_never_becomes_trusted_client_identity():
    registry = SessionRegistry()
    record = registry.login_attacker("tok-3", "John")
    assert record["role"] == ATTACKER
    assert record["client_id"].startswith("ATTACKER-")
    assert record["display_name"] == "AUTHORIZED SECURITY TEST"
    # the typed username is retained as a label, but the identity is not it
    assert record["username"] == "John"
    assert record["client_id"] != "John"


def test_repeat_login_with_same_token_reuses_identity():
    registry = SessionRegistry()
    first = registry.login_client("tok-1", "Alice")
    second = registry.login_client("tok-1", "Alice")
    assert first["client_id"] == second["client_id"]


def test_register_socket_and_role_check():
    registry = SessionRegistry()
    login = registry.login_attacker("tok-9", "Eve")
    session = registry.register_socket("sid-1", login, "10.0.0.9")
    assert session["role"] == ATTACKER
    assert registry.is_attacker("sid-1") is True
    assert registry.get("sid-1")["client_id"] == login["client_id"]


def test_client_socket_is_not_attacker():
    registry = SessionRegistry()
    login = registry.login_client("tok-5", "Alice")
    registry.register_socket("sid-2", login, "10.0.0.5")
    assert registry.is_attacker("sid-2") is False


def test_unregister_socket_removes_session():
    registry = SessionRegistry()
    login = registry.login_client("tok-5", "Alice")
    registry.register_socket("sid-2", login, "10.0.0.5")
    removed = registry.unregister_socket("sid-2")
    assert removed["client_id"] == login["client_id"]
    assert registry.get("sid-2") is None


def test_snapshot_separates_roles():
    registry = SessionRegistry()
    c = registry.login_client("tok-a", "Alice")
    a = registry.login_attacker("tok-b", "Mallory")
    registry.register_socket("sid-a", c, "10.0.0.1")
    registry.register_socket("sid-b", a, "10.0.0.2")
    snap = registry.snapshot()
    assert snap["total_sessions"] == 2
    assert len(snap["clients"]) == 1
    assert len(snap["attackers"]) == 1
