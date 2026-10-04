from identity import IdentityRegistry


def test_register_and_context_lookup():
    registry = IdentityRegistry()
    registry.register("192.168.1.10", "sid-1", "alice", ts=100.0)
    context = registry.context_for("192.168.1.10")
    assert context is not None
    assert context["name"] == "alice"
    assert context["sid"] == "sid-1"
    assert registry.is_known("192.168.1.10") is True


def test_unknown_ip_returns_none():
    registry = IdentityRegistry()
    assert registry.context_for("10.10.10.10") is None
    assert registry.is_known("10.10.10.10") is False


def test_disconnect_marks_not_known_but_keeps_history():
    registry = IdentityRegistry()
    registry.register("192.168.1.10", "sid-1", "alice", ts=100.0)
    registry.disconnect("192.168.1.10", "sid-1", ts=200.0)
    assert registry.is_known("192.168.1.10") is False
    context = registry.context_for("192.168.1.10")
    assert context is not None
    assert context["disconnected_at"] == 200.0


def test_reconnect_increments_session_count():
    registry = IdentityRegistry()
    registry.register("192.168.1.10", "sid-1", "alice", ts=100.0)
    registry.register("192.168.1.10", "sid-2", "alice", ts=300.0)
    context = registry.context_for("192.168.1.10")
    assert context["session_count"] == 2
