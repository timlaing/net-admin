"""DNS agent authentication, migration and rollback."""

import subprocess
from types import SimpleNamespace

from netadmin.agents.dns import create_dns_agent

AUTH = {"Authorization": "Bearer synthetic"}


def agent(tmp_path, monkeypatch):
    main = tmp_path / "named.conf"
    main.write_text('include "legacy.conf";\n')
    zones = tmp_path / "zones"
    zones.mkdir()
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("DNS_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DNS_MANAGED_CONFIG", str(tmp_path / "managed.conf"))
    monkeypatch.setenv("DNS_ZONE_DIR", str(zones))
    canonical = (
        'key "rndc-key" { algorithm hmac-sha256; secret "YWJj"; };\n'
        'zone "existing.example" { type primary; file "existing.zone"; };\n'
    )
    monkeypatch.setattr(
        "netadmin.agents.dns.subprocess.run", lambda *a, **k: SimpleNamespace(stdout=canonical)
    )
    return create_dns_agent().test_client(), main


def test_discovery_and_creation_migrate_without_losing_existing_zones(tmp_path, monkeypatch):
    client, main = agent(tmp_path, monkeypatch)
    assert client.get("/zones").status_code == 401
    assert client.get("/zones", headers=AUTH).json[0]["name"] == "existing.example"
    response = client.post(
        "/zones", headers=AUTH, json={"name": "new.example", "content": "synthetic zone data"}
    )
    assert response.status_code == 201
    managed = (tmp_path / "managed.conf").read_text()
    assert "existing.example" in managed
    assert "new.example" in managed
    assert (tmp_path / "named.conf.before-netadmin").read_text() == 'include "legacy.conf";\n'
    assert "managed.conf" in main.read_text()


def test_failed_validation_restores_original_and_removes_new_files(tmp_path, monkeypatch):
    client, main = agent(tmp_path, monkeypatch)

    def command(args, **kwargs):
        if "-z" in args:
            raise subprocess.CalledProcessError(1, args, stderr="private configuration")
        return SimpleNamespace(stdout='key "rndc-key" { algorithm hmac-sha256; secret "YWJj"; };\n')

    monkeypatch.setattr("netadmin.agents.dns.subprocess.run", command)
    response = client.post(
        "/zones", headers=AUTH, json={"name": "new.example", "content": "invalid"}
    )
    assert response.status_code == 502
    assert "private configuration" not in response.text
    assert main.read_text() == 'include "legacy.conf";\n'
    assert not (tmp_path / "managed.conf").exists()
    assert not (tmp_path / "zones/new.example.zone").exists()


def test_deletion_preserves_zone_data(tmp_path, monkeypatch):
    client, _ = agent(tmp_path, monkeypatch)
    retained = tmp_path / "zones/existing.zone"
    retained.write_text("retain me")
    assert (
        client.post("/zones/delete", headers=AUTH, json={"name": "existing.example"}).status_code
        == 200
    )
    assert retained.read_text() == "retain me"
    assert "existing.example" not in (tmp_path / "managed.conf").read_text()


def test_web_zone_operations_use_agent_and_do_not_write_service_files(tmp_path, monkeypatch):
    from dataclasses import replace

    from netadmin.app import create_app
    from netadmin.config import Settings

    settings = Settings(secret_key="synthetic", root_password_hash="unused", data_dir=tmp_path)  # noqa: S106
    app = create_app(replace(settings, dns_agent_url="https://dns:8083"))
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    calls = []
    remote = app.extensions["netadmin_dns"].zone_agent
    monkeypatch.setattr(
        remote,
        "get",
        lambda path: [{"name": "example.net", "file": "example.zone", "dynamic": True}],
    )
    monkeypatch.setattr(remote, "post", lambda path, body: calls.append((path, body)))
    client = app.test_client()
    token = app.extensions["netadmin_store"].create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", token)
    response = client.get("/dns")
    assert response.status_code == 200
    assert "example.net" in response.text
    assert "Create authoritative zone" in response.text
    assert (
        client.post("/dns/zones", data={"name": "new.example", "content": "zone data"}).status_code
        == 302
    )
    assert client.post("/dns/zones/delete", data={"zone": "example.net"}).status_code == 302
    assert [path for path, _ in calls] == ["zones", "zones/delete"]


def test_agent_uses_configured_tsig_name_unless_explicitly_overridden(monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("NETADMIN_DNS_TSIG_NAME", "custom-update")
    monkeypatch.delenv("DNS_UPDATE_KEY", raising=False)
    assert create_dns_agent().config["DNS_UPDATE_KEY"] == "custom-update"
    monkeypatch.setenv("DNS_UPDATE_KEY", "explicit-update")
    assert create_dns_agent().config["DNS_UPDATE_KEY"] == "explicit-update"
