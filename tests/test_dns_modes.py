"""Exclusive DNS transports and agent-owned record credentials."""

from dataclasses import replace
from pathlib import Path

import pytest

from netadmin.config import Settings
from netadmin.connections import configuration_errors, connection_extensions, connection_values
from netadmin.connections import test_connection as probe
from netadmin.preferences import read_env_file
from netadmin.services.dns import AgentDnsService, BindService
from tests.test_connections import client_for, form_data
from tests.test_dns_agent import AUTH, agent


def settings(tmp_path):
    return Settings(
        secret_key="synthetic",  # noqa: S106 - synthetic
        root_password_hash="unused",  # noqa: S106 - synthetic
        data_dir=tmp_path,
        dns_use_agent=True,
        dns_agent_url="https://dns:8083",
        dns_tsig_secret="invalid-unused",  # noqa: S106
        dns_config_path=Path("unused/relative"),
        dhcp_enabled=False,
        radius_enabled=False,
        agent_token="synthetic",  # noqa: S106 - synthetic
        agent_cert=tmp_path / "client.crt",
        agent_key=tmp_path / "client.key",
    )


def test_agent_mode_needs_no_direct_bind_settings_and_routes_all_record_operations(
    tmp_path, monkeypatch
):
    runtime = settings(tmp_path)
    assert configuration_errors(connection_values(runtime)) == {}
    service = connection_extensions(runtime)["netadmin_dns"]
    assert isinstance(service, AgentDnsService)
    calls = []
    monkeypatch.setattr(
        service.client,
        "get",
        lambda path: [{"name": "host", "ttl": 300, "record_type": "A", "value": "192.0.2.1"}],
    )
    monkeypatch.setattr(service.client, "post", lambda path, payload: calls.append((path, payload)))
    assert service.records("example.net")[0].value == "192.0.2.1"
    service.upsert("example.net", "host", "A", 300, "192.0.2.2")
    service.delete("example.net", "host", "A", "192.0.2.2")
    assert [path for path, _ in calls] == ["records", "records/delete"]
    values = connection_values(runtime)
    values["dns_agent_url"] = ""
    assert "dns_agent_url" in configuration_errors(values)


def test_direct_mode_ignores_retained_agent_url(tmp_path):
    runtime = replace(
        settings(tmp_path), dns_use_agent=False, dns_tsig_secret="", dns_config_path=None
    )
    service = connection_extensions(runtime)["netadmin_dns"]
    assert type(service) is BindService
    assert service.zone_agent is None
    assert "dns_tsig_secret" in configuration_errors(connection_values(runtime))


def test_toggle_saves_reloads_and_preserves_inactive_settings(tmp_path, monkeypatch):
    runtime = settings(tmp_path)
    client = client_for(runtime, monkeypatch)
    assert client.post("/settings", data=form_data(runtime)).status_code == 302
    assert read_env_file()["NETADMIN_DNS_USE_AGENT"] == "true"
    saved = client.application.extensions["netadmin_settings"]
    assert saved.dns_tsig_secret == runtime.dns_tsig_secret
    assert isinstance(client.application.extensions["netadmin_dns"], AgentDnsService)
    data = form_data(
        saved, dns_enabled="false", dns_use_agent="false", dns_config_path="", dns_tsig_secret=""
    )
    assert client.post("/settings", data=data).status_code == 302
    assert read_env_file()["NETADMIN_DNS_USE_AGENT"] == "false"
    assert client.application.extensions["netadmin_dns"].zone_agent is None
    assert client.application.extensions["netadmin_settings"].dns_agent_url == runtime.dns_agent_url


def test_legacy_environment_infers_mode_but_explicit_toggle_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_SECRET_KEY", "synthetic")
    monkeypatch.setenv("NETADMIN_ROOT_PASSWORD_HASH", "unused")
    monkeypatch.setenv("NETADMIN_DNS_AGENT_URL", "https://dns:8083")
    monkeypatch.delenv("NETADMIN_DNS_USE_AGENT", raising=False)
    assert Settings.from_env().dns_use_agent is True
    monkeypatch.setenv("NETADMIN_DNS_USE_AGENT", "false")
    assert Settings.from_env().dns_use_agent is False


def test_agent_diagnostic_uses_agent_without_resolving_direct_bind(tmp_path, monkeypatch):
    runtime = settings(tmp_path)

    def get(_client, path):
        return [{"name": "example.net", "file": "zone", "dynamic": True}] if path == "zones" else []

    monkeypatch.setattr("netadmin.services.agents.AgentClient.get", get)
    monkeypatch.setattr(
        "netadmin.connections.socket.getaddrinfo",
        lambda *args, **kwargs: pytest.fail("Direct Bind resolution"),
    )
    assert probe(runtime, "dns").state == "Connected"


@pytest.mark.parametrize(
    "change",
    [
        {"zone": "outside.example"},
        {"name": "host.outside.example."},
        {"record_type": "SOA"},
        {"ttl": False},
        {"ttl": -1},
    ],
)
def test_agent_rejects_unmanaged_or_protected_record_updates(tmp_path, monkeypatch, change):
    client, _ = agent(tmp_path, monkeypatch)
    payload = {
        "zone": "existing.example",
        "name": "host",
        "record_type": "A",
        "ttl": 300,
        "value": "192.0.2.1",
    }
    response = client.post("/records", headers=AUTH, json=payload | change)
    assert response.status_code == 400
    assert "YWJj" not in response.text
    assert client.get("/records?zone=existing.example").status_code == 401
