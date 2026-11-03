"""Regression coverage for atomic files, authenticated DNS and supervised workers."""

import base64
import io
import json
import subprocess
import uuid
from types import SimpleNamespace

import dns.name
import dns.rcode
import dns.zone
import pytest
from flask import Flask, current_app

from netadmin import addon_options, auth
from netadmin.agents import common, radius_renewal
from netadmin.config import Settings
from netadmin.services.dns import BindService


def test_atomic_write_validates_candidate_and_reloads_only_installed_content(tmp_path, monkeypatch):
    path = tmp_path / "managed.conf"
    path.write_text("old")
    events = []

    def validate(candidate):
        assert candidate != path
        assert candidate.read_text() == "new"
        assert path.read_text() == "old"
        events.append("validated")

    def reload(command, **kwargs):
        assert command == ["daemon", "reload"]
        assert kwargs == {"check": True, "timeout": 30}
        assert path.read_text() == "new"
        events.append("reloaded")

    monkeypatch.setattr(subprocess, "run", reload)
    common.atomic_validated_write(path, "new", validate, ["daemon", "reload"])
    assert events == ["validated", "reloaded"]
    assert path.read_text() == "new"
    assert path.stat().st_mode & 0o777 == 0o640
    assert len(list(tmp_path.glob("*.bak"))) == 1
    assert len(list(tmp_path.glob(".managed.conf.*"))) == 0


def test_atomic_write_rolls_back_failed_reload_and_never_installs_invalid_candidate(
    tmp_path, monkeypatch
):
    path = tmp_path / "managed.conf"
    path.write_text("original")

    def fail(command, **_kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        common.atomic_validated_write(
            path, "replacement", lambda _candidate: None, ["daemon", "reload"]
        )
    assert path.read_text() == "original"
    assert not list(tmp_path.glob(".managed.conf.*"))

    def invalid(_candidate):
        raise ValueError("invalid service configuration")

    with pytest.raises(ValueError):
        common.atomic_validated_write(path, "invalid", invalid, [])
    assert path.read_text() == "original"
    created = tmp_path / "new.conf"
    common.atomic_validated_write(created, "initial", lambda _candidate: None, [])
    assert created.read_text() == "initial"


def test_agent_requires_token_and_rejects_nonobject_json(monkeypatch):
    monkeypatch.delenv("NETADMIN_AGENT_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="must be set"):
        common.create_agent("missing-token")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic-bearer")
    app = common.create_agent("json-boundary")
    app.add_url_rule("/object", view_func=common.json_object, methods=["POST"])
    result = app.test_client().post(
        "/object", json=[], headers={"Authorization": "Bearer synthetic-bearer"}
    )
    assert result.status_code == 400
    assert b"JSON object required" in result.data


def test_bind_axfr_and_updates_use_authenticated_transport_and_return_sorted_records(monkeypatch):
    secret = base64.b64encode(b"synthetic-dns-secret").decode()
    bind = BindService("192.0.2.53", "netadmin", secret, port=5353)
    transfer = object()
    calls = []

    def xfr(server, zone, **kwargs):
        assert (server, zone) == ("192.0.2.53", "example.test")
        assert kwargs == {
            "keyring": bind.keyring,
            "keyname": "netadmin",
            "relativize": True,
            "lifetime": 10,
            "port": 5353,
        }
        return transfer

    zone = dns.zone.from_text("""$ORIGIN example.test.
@ 300 IN SOA ns.example.test. admin.example.test. 1 3600 600 86400 300
@ 300 IN NS ns.example.test.
z 60 IN A 192.0.2.2
a 120 IN A 192.0.2.1
""")

    def from_xfr(value):
        assert value is transfer
        return zone

    monkeypatch.setattr(dns.query, "xfr", xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", from_xfr)
    records = bind.records("example.test")
    assert [(record.name, record.value) for record in records if record.record_type == "A"] == [
        ("a", "192.0.2.1"),
        ("z", "192.0.2.2"),
    ]
    response = SimpleNamespace(rcode=lambda: 0)

    def tcp(update, server, **kwargs):
        assert server == "192.0.2.53"
        assert kwargs == {"port": 5353, "timeout": 10}
        assert update.keyname == dns.name.from_text("netadmin")
        calls.append(update)
        return response

    monkeypatch.setattr(dns.query, "tcp", tcp)
    bind.upsert("example.test", "host", "A", 300, "192.0.2.9")
    assert calls[-1].authority[-1].ttl == 300
    assert calls[-1].authority[-1][0].address == "192.0.2.9"
    bind.delete("example.test", "host", "A", "192.0.2.9")
    assert calls[-1].authority[-1][0].address == "192.0.2.9"
    bind.delete("example.test", "host", "A")
    assert len(calls[-1].authority[-1]) == 0
    response.rcode = lambda: dns.rcode.REFUSED
    with pytest.raises(RuntimeError, match="DNS update failed"):
        bind.upsert("example.test", "host", "A", 300, "192.0.2.9")
    with pytest.raises(RuntimeError, match="DNS delete failed"):
        bind.delete("example.test", "host", "A")


def test_paired_dns_creation_compensates_failed_reverse_update(monkeypatch):
    bind = BindService("192.0.2.53", "", "")
    calls = []

    def upsert(*arguments):
        calls.append(("upsert", arguments))
        if arguments[2] == "PTR":
            raise OSError("reverse zone unavailable")

    monkeypatch.setattr(bind, "records", lambda _zone: [])
    monkeypatch.setattr(bind, "upsert", upsert)
    monkeypatch.setattr(bind, "delete", lambda *args: calls.append(("delete", args)))
    with pytest.raises(OSError):
        bind.add_host("node", "192.0.2.9", "example.test", "2.0.192.in-addr.arpa", 600)
    assert calls == [
        ("upsert", ("example.test", "node", "A", 600, "192.0.2.9")),
        ("upsert", ("2.0.192.in-addr.arpa", "9", "PTR", 600, "node.example.test.")),
        ("delete", ("example.test", "node", "A", "192.0.2.9")),
    ]


def test_radius_renewal_worker_retains_identity_and_does_not_log_secret_exception(
    monkeypatch, caplog
):
    app = Flask("synthetic-renewal")
    monkeypatch.setattr(radius_renewal, "create_radius_agent", lambda: app)
    outcomes = iter([True, False, ValueError("synthetic-private-token")])

    def renew():
        assert current_app.name == app.name
        result = next(outcomes)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(radius_renewal, "renew_once", renew)

    class Stop(BaseException):
        pass

    sleeps = []

    def sleep(seconds):
        assert seconds == 60
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise Stop

    monkeypatch.setattr(radius_renewal.time, "sleep", sleep)
    with caplog.at_level("INFO"), pytest.raises(Stop):
        radius_renewal.main()
    assert "renewed and activated" in caplog.text
    assert "previous identity retained" in caplog.text
    assert "synthetic-private-token" not in caplog.text
    assert len(sleeps) == 3


def test_legacy_options_cli_validates_object_and_prints_only_retired_names(monkeypatch, capsys):
    monkeypatch.setattr(addon_options.sys, "stdin", io.StringIO("[]"))
    with pytest.raises(ValueError, match="JSON object"):
        addon_options.main()
    monkeypatch.setattr(
        addon_options.sys,
        "stdin",
        io.StringIO(json.dumps({"dns_server": "synthetic.example", "password": "never-print"})),
    )
    monkeypatch.setattr(addon_options, "read_env_file", lambda: {})
    saved = []
    monkeypatch.setattr(addon_options, "write_env_file", lambda values: saved.append(values))
    addon_options.main()
    assert capsys.readouterr().out == "dns_server\n"
    assert saved == [{"NETADMIN_DNS_SERVER": "synthetic.example"}]


def test_radius_explicit_standard_and_unknown_role_contract(tmp_path, monkeypatch):
    settings = Settings(
        secret_key=uuid.uuid4().hex,
        root_password_hash=uuid.uuid4().hex,
        data_dir=tmp_path,
        radius_secret=uuid.uuid4().hex,
    )
    result = SimpleNamespace(
        returncode=0, stdout='Access-Accept\nFilter-Id = "netadmin-standard"\n'
    )
    monkeypatch.setattr(auth.subprocess, "run", lambda *_args, **_kwargs: result)
    assert auth.authenticate_radius("ordinary", "synthetic-password", settings) == "standard"
    result.stdout = 'Access-Accept\nFilter-Id = "unknown-role"\n'
    assert auth.authenticate_radius("ordinary", "synthetic-password", settings) == "standard"


def test_paired_dns_failure_restores_complete_previous_rrset_and_ttl(monkeypatch):
    from netadmin.services.dns import DnsRecord

    bind = BindService("192.0.2.53", "", "")
    original = [DnsRecord("node", 3600, "A", value) for value in ("192.0.2.10", "192.0.2.11")]
    monkeypatch.setattr(bind, "records", lambda _zone: original)
    calls = []

    def upsert(*args):
        if args[2] == "PTR":
            raise OSError("synthetic PTR failure")

    def update(message, server, **kwargs):
        calls.append(message)
        assert server == "192.0.2.53"
        assert kwargs == {"port": 53, "timeout": 10}
        return SimpleNamespace(rcode=lambda: 0)

    monkeypatch.setattr(bind, "upsert", upsert)
    monkeypatch.setattr("dns.query.tcp", update)
    with pytest.raises(OSError, match="PTR failure"):
        bind.add_host("node", "192.0.2.9", "example.test", "2.0.192.in-addr.arpa", 600)
    records = [rrset for rrset in calls[0].authority if len(rrset)]
    assert {rrset.ttl for rrset in records} == {3600}
    assert {item.to_text() for rrset in records for item in rrset} == {"192.0.2.10", "192.0.2.11"}
    assert len(calls) == 1
    monkeypatch.setattr("dns.query.tcp", lambda *_args, **_kwargs: SimpleNamespace(rcode=lambda: 5))
    with pytest.raises(RuntimeError, match="rollback failed"):
        bind.restore_addresses("example.test", "node", original)


def test_agent_dns_rollback_never_bypasses_agent():
    from netadmin.services.dns import AgentDnsService, DnsRecord

    calls = []
    bind = AgentDnsService(SimpleNamespace(post=lambda *args: calls.append(args)))
    bind.restore_addresses("example.test", "node", [DnsRecord("node", 300, "A", "192.0.2.10")])
    assert calls == [
        (
            "records",
            {
                "zone": "example.test",
                "name": "node",
                "record_type": "A",
                "ttl": 300,
                "values": ["192.0.2.10"],
            },
        )
    ]
