"""Settings authorization, restart persistence and read-only diagnostics."""

import socket
import ssl
import subprocess
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from netadmin.app import create_app
from netadmin.auth import authenticate_radius
from netadmin.config import Settings
from netadmin.connections import (
    configuration_errors,
    connection_values,
)
from netadmin.connections import (
    test_connection as probe_connection,
)
from netadmin.preferences import read_env_file, write_env_file


@pytest.fixture
def runtime(tmp_path):
    return Settings(
        secret_key="synthetic",  # noqa: S106 - synthetic test value
        root_password_hash="unused",  # noqa: S106 - synthetic test value
        data_dir=tmp_path,
        dns_enabled=False,
        dhcp_enabled=False,
        radius_enabled=False,
    )


def client_for(runtime, monkeypatch, role="admin", addon=True):
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(runtime.data_dir / "netadmin.env"))
    monkeypatch.setenv("NETADMIN_ADDON", "1" if addon else "0")
    app = create_app(runtime)
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    client = app.test_client()
    if role:
        token = app.extensions["netadmin_store"].create_session("operator", role, 3600)
        client.set_cookie("netadmin_session", token)
    return client


def form_data(runtime, **changes):
    values = connection_values(runtime)
    values.update(changes)
    return {
        key: value
        for key, value in values.items()
        if not key.endswith("_enabled") or value == "true"
    }


@pytest.mark.parametrize("role,expected", [(None, 302), ("standard", 403)])
def test_settings_and_tests_require_admin(runtime, monkeypatch, role, expected) -> None:
    client = client_for(runtime, monkeypatch, role=role)
    assert client.get("/settings").status_code == expected
    assert client.post("/settings", data=form_data(runtime)).status_code == expected
    assert client.post("/settings/test/dns").status_code == expected
    assert not (runtime.data_dir / "netadmin.env").exists()


def test_save_preserves_secrets_and_applies_without_restart(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    write_env_file(
        {"NETADMIN_SECRET_KEY": "keep-session-key", "NETADMIN_AGENT_TOKEN": "keep-token"}
    )
    response = client.post(
        "/settings", data=form_data(runtime, agent_token="", dns_server="new.example")
    )
    assert response.status_code == 302
    saved = read_env_file()
    assert saved["NETADMIN_SECRET_KEY"] == "keep-session-key"  # noqa: S105 - synthetic
    assert saved["NETADMIN_AGENT_TOKEN"] == "keep-token"  # noqa: S105 - synthetic
    assert saved["NETADMIN_DNS_SERVER"] == "new.example"
    assert client.application.extensions["netadmin_settings"].dns_server == "new.example"
    page = client.get("/settings").text
    assert "Saved settings differ" not in page
    assert "keep-token" not in page
    assert "keep-session-key" not in page
    for key, value in saved.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("NETADMIN_ROOT_PASSWORD_HASH", "unused")
    monkeypatch.setenv("NETADMIN_DATA_DIR", str(runtime.data_dir))
    assert Settings.from_env().dns_server == "new.example"
    assert Settings.from_env().dns_enabled is False


def test_invalid_enabled_service_does_not_save(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    response = client.post(
        "/settings", data=form_data(runtime, dhcp_enabled="true", dhcp_agent_url="http://insecure")
    )
    assert response.status_code == 200
    assert "Enter an HTTPS agent URL" in response.text
    assert "Required for enabled agents" in response.text
    assert not (runtime.data_dir / "netadmin.env").exists()


def test_settings_and_diagnostics_keep_csrf(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/settings", data=form_data(runtime)).status_code == 400
    assert client.post("/settings/test/dns").status_code == 400


def test_standalone_settings_are_read_only(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch, addon=False)
    assert "standalone deployment" in client.get("/settings").text
    assert client.post("/settings", data=form_data(runtime)).status_code == 403
    assert not (runtime.data_dir / "netadmin.env").exists()


def test_disabled_services_never_call_backends(runtime, monkeypatch) -> None:
    def unexpected(*args, **kwargs):
        pytest.fail("Disabled service must not be contacted")

    monkeypatch.setattr("netadmin.services.agents.AgentClient.get", unexpected)
    monkeypatch.setattr("netadmin.services.dns.BindService.records", unexpected)
    monkeypatch.setattr("netadmin.auth.subprocess.run", unexpected)
    client = client_for(runtime, monkeypatch)
    for service in ("dns", "dhcp", "radius"):
        response = client.get(f"/{service}")
        assert response.location == "/settings"
        assert "Disabled" in client.post(f"/settings/test/{service}").text
    assert authenticate_radius("alice", "synthetic-password", runtime) is None


@pytest.mark.parametrize(
    "changes,field",
    [
        ({"dns_enabled": "true"}, "dns_tsig_secret"),
        ({"dns_enabled": "true", "dns_tsig_secret": "not-base64"}, "dns_tsig_secret"),
        ({"dns_enabled": "true", "dns_tsig_secret": "YWJj"}, "dns_zones"),
        ({"agent_cert": "relative.pem"}, "agent_cert"),
        ({"agent_key": "/config/../key.pem"}, "agent_key"),
        ({"radius_enabled": "true", "radius_host": ""}, "radius_host"),
        ({"dhcp_enabled": "true", "dhcp_agent_url": "https://user:secret@agent"}, "dhcp_agent_url"),
        ({"dhcp_enabled": "true", "dhcp_agent_url": "https://agent:invalid"}, "dhcp_agent_url"),
    ],
)
def test_configuration_validation(runtime, changes, field) -> None:
    values = connection_values(runtime)
    values.update(changes)
    assert field in configuration_errors(values)


def test_incomplete_connection_does_not_probe(runtime, monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("Must validate first"))
    assert probe_connection(replace(runtime, dns_enabled=True), "dns").state == "Not configured"


@pytest.fixture
def agent_settings(runtime):
    return replace(
        runtime,
        dhcp_enabled=True,
        dhcp_agent_url="https://agent.example:8081",
        agent_token="synthetic-token",  # noqa: S106 - synthetic test value
        agent_cert=Path("/config/client.pem"),
        agent_key=Path("/config/client.key"),
    )


def test_agent_probe_is_health_only(agent_settings, monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    paths = []

    def health(_client, path):
        paths.append(path)
        return {"status": "ok"}

    monkeypatch.setattr("netadmin.connections.AgentClient.get", health)
    result = probe_connection(agent_settings, "dhcp")
    assert result.state == "Connected"
    assert "write/reload permissions were not tested" in result.message
    assert paths == ["health"]


@pytest.mark.parametrize(
    "error,text",
    [
        (socket.gaierror("sensitive details"), "Hostname resolution failed"),
        (ssl.SSLError("sensitive details"), "TLS configuration failed"),
        (FileNotFoundError("sensitive details"), "TLS configuration failed"),
        (httpx.ReadTimeout("sensitive details"), "Connection timed out"),
        (httpx.ConnectError("sensitive details"), "Connection failed"),
    ],
)
def test_diagnostic_failures_are_actionable_and_redacted(
    agent_settings, monkeypatch, error, text
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])

    def failed(_client, _path):
        raise error

    monkeypatch.setattr("netadmin.connections.AgentClient.get", failed)
    result = probe_connection(agent_settings, "dhcp")
    assert result.state == "Unavailable"
    assert text in result.message
    assert "sensitive details" not in result.message


@pytest.mark.parametrize(
    "status,text",
    [(401, "rejected authentication"), (403, "rejected authentication"), (500, "HTTP error")],
)
def test_agent_http_errors(agent_settings, monkeypatch, status, text) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])

    def failed(_client, _path):
        request = httpx.Request("GET", "https://agent.example/health")
        raise httpx.HTTPStatusError("private", request=request, response=httpx.Response(status))

    monkeypatch.setattr("netadmin.connections.AgentClient.get", failed)
    assert text in probe_connection(agent_settings, "dhcp").message


def test_dns_probe_reads_first_zone_only(runtime, monkeypatch) -> None:
    runtime = replace(
        runtime,
        dns_enabled=True,
        dns_tsig_secret="YWJj",  # noqa: S106 - synthetic
        dns_zones=("example.net", "other.net"),
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    zones = []

    def records(_bind, zone):
        zones.append(zone)
        return [object(), object()]

    monkeypatch.setattr("netadmin.connections.BindService.records", records)
    result = probe_connection(runtime, "dns")
    assert result.state == "Connected"
    assert "2 records" in result.message
    assert "update permissions were not tested" in result.message
    assert zones == ["example.net"]


def test_settings_file_round_trips_shell_metacharacters(runtime, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(runtime.data_dir / "netadmin.env"))
    value = "quote' $(false) `false` spaces $HOME"
    write_env_file({"NETADMIN_AGENT_TOKEN": value, "NETADMIN_DNS_ZONES": ""})
    write_env_file({"NETADMIN_DNS_SERVER": "bind.example"})
    assert read_env_file()["NETADMIN_AGENT_TOKEN"] == value
    # Source the generated file as the real entrypoint does. Metacharacters must stay literal.
    result = subprocess.run(  # noqa: S603 - fixed shell script and synthetic file
        [
            "/bin/sh",
            "-c",
            '. "$1"; printf "%s" "$NETADMIN_AGENT_TOKEN"',
            "probe",
            str(runtime.data_dir / "netadmin.env"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == value
    assert read_env_file()["NETADMIN_DNS_ZONES"] == ""


@pytest.mark.parametrize("values", [{"BAD_KEY": "x"}, {"NETADMIN_AGENT_TOKEN": "x\nBAD=1"}])
def test_unsafe_assignments_rejected(runtime, monkeypatch, values) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(runtime.data_dir / "netadmin.env"))
    with pytest.raises(ValueError):
        write_env_file(values)
    assert not (runtime.data_dir / "netadmin.env").exists()


def test_entrypoint_saved_settings_override_legacy_options(runtime, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    write_env_file({"NETADMIN_DNS_SERVER": "saved.example", "NETADMIN_DNS_ZONES": ""})
    stub = tmp_path / "gunicorn"
    stub.write_text('#!/bin/sh\nprintf "%s|%s" "$NETADMIN_DNS_SERVER" "$NETADMIN_DNS_ZONES"\n')
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    script = Path(__file__).resolve().parents[1] / "home-assistant/netadmin/run.sh"
    result = subprocess.run(  # noqa: S603 - fixed entrypoint and synthetic Bashio function
        [
            "/bin/bash",
            "-c",
            'function bashio::config() { printf legacy; }; source "$1"',
            "probe",
            str(script),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "saved.example|"


def test_normalized_settings_do_not_stay_pending_after_restart(runtime, monkeypatch) -> None:
    runtime = replace(
        runtime, dns_zones=("example.net", "other.net"), agent_ca=Path("/config/pki/ca.pem")
    )
    client = client_for(runtime, monkeypatch)
    response = client.post(
        "/settings",
        data=form_data(
            runtime, dns_zones="example.net, other.net, ,", agent_ca="/config//pki/ca.pem"
        ),
    )
    assert response.status_code == 302
    assert read_env_file()["NETADMIN_DNS_ZONES"] == "example.net,other.net"
    assert "Saved settings differ" not in client.get("/settings").text


def test_empty_zone_separators_are_not_a_configured_zone(runtime) -> None:
    values = connection_values(runtime)
    values.update(dns_enabled="true", dns_tsig_secret="YWJj", dns_zones=", ,")  # noqa: S106
    assert "dns_zones" in configuration_errors(values)


def test_default_agent_connections_require_tls_and_credentials(runtime) -> None:
    assert runtime.dhcp_agent_url.startswith("https://")
    assert runtime.radius_agent_url.startswith("https://")
    result = probe_connection(replace(runtime, dhcp_enabled=True), "dhcp")
    assert result.state == "Not configured"
    assert "mTLS" in result.message


def test_save_changes_backends_and_navigation_without_losing_session(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    response = client.post(
        "/settings",
        data=form_data(
            runtime,
            dhcp_enabled="true",
            dhcp_agent_url="https://new.example:8081",
            agent_token="synthetic",  # noqa: S106 - synthetic
            agent_cert="/config/client.pem",
            agent_key="/config/client.key",
        ),
    )
    assert response.status_code == 302
    assert client.application.extensions["netadmin_dhcp"].base_url == "https://new.example:8081"
    assert "Manage DHCP" in client.get("/").text
    assert "Configure DNS" in client.get("/").text
    monkeypatch.setattr("netadmin.services.agents.AgentClient.get", lambda *a: [])
    assert client.get("/dhcp").status_code == 200
    assert client.get("/settings").status_code == 200


def test_save_failure_keeps_active_connections(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    previous = dict(client.application.extensions)

    def fail(_values):
        raise OSError("private details")

    monkeypatch.setattr("netadmin.settings_web.write_env_file", fail)
    response = client.post("/settings", data=form_data(runtime, dns_server="new.example"))
    assert response.status_code == 503
    assert "private details" not in response.text
    for key in ("netadmin_settings", "netadmin_dns", "netadmin_dhcp", "netadmin_radius"):
        assert client.application.extensions[key] is previous[key]


def test_manual_reload_changes_only_connections(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    write_env_file({"NETADMIN_DNS_SERVER": "manual.example", "NETADMIN_SECRET_KEY": "ignored"})
    assert "Saved settings differ" in client.get("/settings").text
    assert client.post("/settings/reload").status_code == 302
    active = client.application.extensions["netadmin_settings"]
    assert active.dns_server == "manual.example"
    assert active.secret_key == runtime.secret_key
    assert "Saved settings differ" not in client.get("/settings").text


def test_invalid_manual_reload_keeps_active_settings(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch)
    write_env_file({"NETADMIN_DNS_ENABLED": "not-a-boolean"})
    assert client.post("/settings/reload").status_code == 400
    assert client.application.extensions["netadmin_settings"] is runtime
    client.application.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/settings/reload").status_code == 400


def test_reload_keeps_auth_and_standalone_boundaries(runtime, monkeypatch) -> None:
    client = client_for(runtime, monkeypatch, role="standard")
    assert client.post("/settings/reload").status_code == 403
    client = client_for(runtime, monkeypatch, role=None)
    assert client.post("/settings/reload").status_code == 302
    client = client_for(runtime, monkeypatch, addon=False)
    assert client.post("/settings/reload").status_code == 403


def test_supervisor_authentication_option_overrides_environment_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    write_env_file({"NETADMIN_INGRESS_REQUIRE_LOGIN": "false"})
    stub = tmp_path / "gunicorn"
    stub.write_text('#!/bin/sh\nprintf "%s" "$NETADMIN_INGRESS_REQUIRE_LOGIN"\n')
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    script = Path(__file__).resolve().parents[1] / "home-assistant/netadmin/run.sh"
    result = subprocess.run(  # noqa: S603 - synthetic Bashio and fixed entrypoint
        [
            "/bin/bash",
            "-c",
            'function bashio::config() { printf true; }; source "$1"',
            "probe",
            str(script),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "true"
