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
    canonical = 'zone "existing.example" { type primary; file "existing.zone"; };\n'
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
    assert "existing.example" in managed and "new.example" in managed
    assert (tmp_path / "named.conf.before-netadmin").read_text() == 'include "legacy.conf";\n'
    assert "managed.conf" in main.read_text()


def test_failed_validation_restores_original_and_removes_new_files(tmp_path, monkeypatch):
    client, main = agent(tmp_path, monkeypatch)

    def command(args, **kwargs):
        if "-z" in args:
            raise subprocess.CalledProcessError(1, args, stderr="private configuration")
        return SimpleNamespace(stdout="")

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
