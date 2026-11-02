"""Controller startup/shutdown and operator-input boundaries."""

import signal
import uuid
from types import SimpleNamespace

import pytest

from netadmin.ca_runtime import app as runtime
from netadmin.ca_runtime.issuer import dns_rule_subset, policy
from tests.test_ca_runtime import TOKEN


@pytest.mark.parametrize("reconcile_fails", [False, True])
def test_controller_main_owns_socket_signals_and_closes_children(
    tmp_path, monkeypatch, caplog, reconcile_fails
):
    token = tmp_path / "token"
    token.write_text(TOKEN)
    socket_path = tmp_path / "control.sock"
    monkeypatch.setenv("CA_MANAGEMENT_TOKEN_FILE", str(token))
    monkeypatch.setenv("CA_RUNTIME_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CA_CONTROL_SOCKET", str(socket_path))
    events = []
    handlers = {}

    class Stop:
        def __init__(self):
            self.stopped = False
            self.polls = 0

        def wait(self, seconds):
            assert seconds == 1
            self.polls += 1
            if self.polls == 2:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            return self.stopped

        def set(self):
            self.stopped = True
            events.append("signal")

    class Thread:
        def __init__(self, target, daemon):
            assert daemon
            self.target = target

        def start(self):
            self.target()

        def join(self, timeout):
            assert timeout == 5
            events.append("joined")

    def server(host, port, app):
        assert (host, port) == ("unix://" + str(socket_path), 0)
        socket_path.touch()
        assert app.extensions["ca_store"].status()["state"] == "key_ready"
        return SimpleNamespace(
            serve_forever=lambda: events.append("serving"),
            shutdown=lambda: events.append("shutdown"),
        )

    def reconcile(_self):
        events.append("reconcile")
        if reconcile_fails:
            raise OSError("synthetic-private-launch-error")

    monkeypatch.setattr(runtime, "make_server", server)
    monkeypatch.setattr(runtime.threading, "Event", Stop)
    monkeypatch.setattr(runtime.threading, "Thread", Thread)
    monkeypatch.setattr(
        runtime.signal, "signal", lambda signum, handler: handlers.__setitem__(signum, handler)
    )
    monkeypatch.setattr(runtime.issuer.Issuers, "reconcile", reconcile)
    monkeypatch.setattr(
        runtime.issuer.Issuers, "close", lambda _self: events.append("children closed")
    )
    runtime.main()
    assert events == ["serving", "reconcile", "signal", "shutdown", "children closed", "joined"]
    assert socket_path.stat().st_mode & 0o777 == 0o660
    assert (tmp_path / "state/root.key").is_file()
    assert set(handlers) == {signal.SIGTERM, signal.SIGINT}
    if reconcile_fails:
        assert "Issuer startup failed" in caplog.text
        assert "synthetic-private-launch-error" not in caplog.text


@pytest.mark.parametrize(
    "values",
    [
        {"dns_suffixes": "*.example.test"},
        {"dns_suffixes": "192.0.2.1"},
        {"ip_ranges": "x" * 4097},
        {},
    ],
)
def test_issuer_policy_requires_explicit_valid_name_scope(values):
    with pytest.raises(ValueError):
        policy(values)


def test_wildcard_subset_does_not_expand_dns_depth():
    assert dns_rule_subset("host.example.test", "*.example.test")
    assert not dns_rule_subset("deep.host.example.test", "*.example.test")
    assert not dns_rule_subset("*.host.example.test", "*.example.test")
    assert not dns_rule_subset("example.test", "*.example.test")


def test_short_management_token_is_rejected_before_creating_state(tmp_path):
    root = tmp_path / uuid.uuid4().hex
    with pytest.raises(ValueError, match="32 characters"):
        runtime.create_runtime(root, "short")
    assert not root.exists()
