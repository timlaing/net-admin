"""Rejected Bind operations, private RADIUS recovery journals and restart acknowledgements."""

import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import dns.query
import pytest
from flask import Flask

from netadmin.agents import dns as dns_agent
from netadmin.agents import radius_certificates, radius_state
from netadmin.agents.common import ConfigurationChanged, validated_transaction
from netadmin.services.agents import AgentClient
from tests.test_dns_agent import AUTH, agent
from tests.test_radius_certificates import PASSWORD
from tests.test_radius_certificates import material as radius_material  # noqa: F401


@pytest.fixture
def certificate_state(request):
    return request.getfixturevalue("radius_material")


@pytest.mark.parametrize(
    "canonical,message",
    [
        ('zone "existing.example" { type primary; file "zone"; };', "TSIG"),
        (
            'key "rndc-key" { secret "YWJj"; };\n'
            'zone "existing.example" { type primary; file "zone"; };',
            "algorithm",
        ),
    ],
)
def test_dns_record_management_requires_complete_locally_declared_tsig(
    tmp_path, monkeypatch, canonical, message
):
    client, _ = agent(tmp_path, monkeypatch)
    monkeypatch.setattr(dns_agent, "_canonical", lambda: canonical)
    response = client.get("/records?zone=existing.example", headers=AUTH)
    assert response.status_code == 400
    assert message.lower() in response.json["error"].lower()


def test_dns_transfer_refusal_and_invalid_names_do_not_call_update(tmp_path, monkeypatch):
    client, _ = agent(tmp_path, monkeypatch)
    calls = []

    def refuse(_zone):
        raise dns.query.TransferError(dns.rcode.REFUSED)

    backend = SimpleNamespace(records=refuse, upsert=lambda *args: calls.append(args))
    monkeypatch.setattr(dns_agent, "_record_backend", lambda _zone: backend)
    assert client.get("/records?zone=existing.example", headers=AUTH).json == {
        "error": "zone_transfer_refused"
    }
    for payload in (
        {"name": "outside.invalid.", "record_type": "A"},
        {"name": "host", "record_type": "INVALID"},
        {"name": "host", "record_type": "NS"},
        {"name": "host", "record_type": "A", "ttl": True},
    ):
        response = client.post(
            "/records",
            headers=AUTH,
            json={"zone": "existing.example", "value": "192.0.2.9", **payload},
        )
        assert response.status_code == 400
    assert not calls


def test_dns_zone_validation_import_guards_and_file_resolution(tmp_path, monkeypatch):
    client, main = agent(tmp_path, monkeypatch)
    original = main.read_bytes()
    for name in ("bad..example", "-bad.example", "bad-.example", "x" * 64 + ".example"):
        assert (
            client.post(
                "/zones", headers=AUTH, json={"name": name, "content": "synthetic"}
            ).status_code
            == 400
        )
    assert (
        client.post(
            "/zones", headers=AUTH, json={"name": "existing.example", "content": "synthetic"}
        ).status_code
        == 409
    )
    assert (
        client.post("/zones", headers=AUTH, json={"name": "new.example", "content": ""}).status_code
        == 400
    )
    (tmp_path / "zones/new.example.zone.jnl").write_text("synthetic retained journal")
    assert (
        client.post(
            "/zones", headers=AUTH, json={"name": "new.example", "content": "synthetic"}
        ).status_code
        == 409
    )
    assert (
        client.post("/zones/delete", headers=AUTH, json={"name": "missing.example"}).status_code
        == 404
    )
    assert client.get("/records?zone=unknown.example&source=file", headers=AUTH).status_code == 400
    assert client.get("/records?zone=existing.example&source=file", headers=AUTH).status_code == 400
    monkeypatch.setattr(
        dns_agent,
        "_canonical",
        lambda: 'zone "other.example" { type primary; file "other.zone"; };',
    )
    assert (
        client.post(
            "/zones", headers=AUTH, json={"name": "valid.example", "content": "synthetic"}
        ).status_code
        == 400
    )
    assert main.read_bytes() == original


def test_dns_block_parser_handles_escaped_quotes_and_rejects_ambiguity():
    text = 'zone "example.test" { type primary; file "escaped\\"{file}"; };'
    assert dns_agent._zone_blocks(text) == [("example.test", 0, len(text))]
    for invalid in (
        'view "private" { };',
        'zone "x" { type primary; }',
        'zone "x" { type primary; };\nzone "x" { type primary; };',
    ):
        with pytest.raises(ValueError):
            dns_agent._zone_blocks(invalid)


def test_radius_restart_acknowledges_fresh_token_and_rejects_stale_reply(tmp_path, monkeypatch):
    app = Flask("restart-protocol")
    app.config.update(
        RADIUS_CERT_DIR=tmp_path,
        RADIUS_CERT_RESTART=["synthetic", "restart"],
        RADIUS_CERT_RESTART_MODE="signal",
    )

    def acknowledge(command, **kwargs):
        assert command == ["synthetic", "restart"]
        assert kwargs == {"check": True, "capture_output": True, "timeout": 5}
        request = tmp_path / ".netadmin-restart-request"
        assert request.stat().st_mode & 0o777 == 0o600
        (tmp_path / ".netadmin-restart-result").write_text(request.read_text())

    monkeypatch.setattr(radius_certificates.subprocess, "run", acknowledge)
    with app.app_context():
        radius_certificates._restart()
    old = (tmp_path / ".netadmin-restart-result").read_text()
    monkeypatch.setattr(radius_certificates.subprocess, "run", lambda *_args, **_kwargs: None)
    clock = iter([0, 0, 13])
    sleeps = []
    monkeypatch.setattr(radius_certificates.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(radius_certificates.time, "sleep", lambda seconds: sleeps.append(seconds))
    with app.app_context(), pytest.raises(RuntimeError, match="did not acknowledge"):
        radius_certificates._restart()
    assert (tmp_path / ".netadmin-restart-request").read_text() != old
    assert sleeps == [0.1]
    app.config["RADIUS_CERT_RESTART"] = []
    with app.app_context(), pytest.raises(ValueError, match="not configured"):
        radius_certificates._restart()


def test_radius_protocol_marker_and_inventory_permissions(certificate_state, monkeypatch):
    directory = certificate_state[0]
    app = Flask("certificate-readiness")
    app.config.update(
        RADIUS_CERT_DIR=directory,
        RADIUS_CERT_RESTART_MODE="signal",
        RADIUS_CERT_RESTART=[],
        RADIUS_CERT_MANAGEMENT=False,
        RADIUS_CERT_KEY_PASSWORD=PASSWORD.decode(),
    )
    with app.app_context():
        assert not radius_certificates._protocol_ready()
        assert "not enabled" in radius_certificates._inventory()["reason"]
        app.config["RADIUS_CERT_MANAGEMENT"] = True
        assert "Update the RADIUS" in radius_certificates._inventory()["reason"]
    (directory / ".netadmin-control").write_text("1")
    original = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: b"radius-supervisor.sh" if str(self) == "/proc/1/cmdline" else original(self),
    )
    with app.app_context():
        assert radius_certificates._protocol_ready()


def test_recovery_rejects_untrusted_journals_and_restores_absent_files(tmp_path, monkeypatch):
    target = tmp_path / "users"
    target.write_text("replacement")
    journal = tmp_path / "journal"
    original = {
        "path": str(target),
        "contents": base64.b64encode(b"original").decode(),
        "mode": 0o640,
        "uid": os.getuid(),
        "gid": os.getgid(),
    }

    def write(entries, state="prepared"):
        journal.write_text(json.dumps({"state": state, "entries": entries}))
        journal.chmod(0o600)

    write([original])
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    with pytest.raises(RuntimeError, match="writable"):
        radius_state.recover(journal, {target}, lambda: None)
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "false")
    journal.chmod(0o644)
    with pytest.raises(ValueError, match="Unsafe"):
        radius_state.recover(journal, {target}, lambda: None)
    for entries in ([], [original, original], [{**original, "path": str(tmp_path / "outside")}]):
        write(entries)
        with pytest.raises(ValueError, match="Unsupported recovery paths"):
            radius_state.recover(journal, {target}, lambda: None)
    write([original], "unknown")
    with pytest.raises(ValueError, match="Unsupported recovery state"):
        radius_state.recover(journal, {target}, lambda: None)
    link = tmp_path / "linked"
    link.symlink_to(target)
    write([{**original, "path": str(link)}])
    with pytest.raises(ValueError, match="paths changed"):
        radius_state.recover(journal, {link}, lambda: None)
    with pytest.raises(ValueError, match="Unsafe lock"), radius_state.file_lock(link):
        pass
    write([{**original, "contents": None}])
    activations = []
    radius_state.recover(journal, {target}, lambda: activations.append(True))
    assert not target.exists() and not journal.exists() and activations == [True]
    write([original])
    with pytest.raises(RuntimeError, match="previous transaction"):
        radius_state.transaction(
            {target: "new"}, lambda: None, [], journal=journal, rollback=lambda: None
        )


def test_optimistic_transaction_does_not_clobber_external_editor(tmp_path):
    path = tmp_path / "users"
    path.write_text("external update")

    def validate():
        pytest.fail("Validation must not run")

    with pytest.raises(ConfigurationChanged):
        validated_transaction(
            {path: "stale"},
            validate,
            [],
            allowed_roots=(tmp_path,),
            expected_originals={path: b"old"},
        )
    assert path.read_text() == "external update"


@pytest.mark.parametrize("method,legacy", [("access_mode", "Unknown"), ("read_only", False)])
def test_agent_capabilities_preserve_legacy_404_and_propagate_real_failures(method, legacy):
    remote = AgentClient("https://agent.test", "synthetic")
    status = [404]

    def get(*_args, **_kwargs):
        response = httpx.Response(
            status[0], request=httpx.Request("GET", "https://agent.test/capabilities")
        )
        response.raise_for_status()

    import httpx

    remote.get = get
    assert getattr(remote, method)() == legacy
    status[0] = 503
    operation = getattr(remote, method)
    with pytest.raises(httpx.HTTPStatusError):
        operation()
