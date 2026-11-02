"""Native log parsing, read-only agent boundaries and service-log UI isolation."""

import os
import time

import httpx
import pytest
from test_app import make_app

from netadmin.agents.dhcp import create_dhcp_agent
from netadmin.agents.dns import create_dns_agent
from netadmin.agents.radius import create_radius_agent
from netadmin.services import service_logs as logs
from netadmin.services.agents import AgentClient
from netadmin.services.dns import AgentDnsService


def detail(status, epoch, session="one", nas="192.0.2.1", extra=""):
    return (
        f'Tue Nov  3 00:00:00 2026\n\tUser-Name = "alice"\n'
        f'\tNAS-IP-Address = {nas}\n\tAcct-Session-Id = "{session}"\n'
        f"\tAcct-Status-Type = {status}\n\tTimestamp = {epoch}\n{extra}\n"
    )


def test_login_redacts_password_and_diagnostics():
    text = (
        "Mon Nov  2 10:00:00 2026 : Auth: Login OK: [alice/SECRET] "
        "(from client ap1 port 0 cli aa:bb:cc:dd:ee:ff)\n"
        "Mon Nov  2 10:01:00 2026 : Auth: Login incorrect (SECRET): [bob] "
        "(from client ap2 port 1)\n"
    )
    rows = logs.login_rows(text)
    assert rows[0]["result"] == "Rejected"
    assert rows[1]["user"] == "alice"
    assert rows[1]["device"] == "aa:bb:cc:dd:ee:ff"
    assert "SECRET" not in str(rows)
    assert logs.login_rows("arbitrary debug User-Password = SECRET") == []


def test_dhcp_and_ddns_native_records():
    rows = logs.dhcp_rows(
        "Nov  2 10:00:00 host dhcpd: DHCPACK on 192.0.2.2 to aa:bb:cc:dd:ee:ff (phone) via eth0\n"
        "2026-11-02 10:01:00.123 DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], lease 192.0.2.3\n"
        "noise\n"
    )
    assert rows[1]["action"] == "DHCPACK"
    assert rows[1]["hostname"] == "phone"
    assert rows[0]["address"] == "192.0.2.3"
    rows = logs.ddns_rows(
        "02-Nov-2026 10:00:00.123 client @0xab 192.0.2.4#123: updating zone 'example/IN': "
        "adding an RR at 'phone.example' A 192.0.2.2\n"
        "02-Nov-2026 10:01:00.123 updating zone 'example/IN': deleting rrset at 'phone.example' A\n"
        "update denied\n"
    )
    assert rows[0]["action"] == "Delete" and rows[0]["value"] == ""
    assert rows[1]["client"] == "192.0.2.4"
    assert rows[1]["value"] == "192.0.2.2"
    assert logs.timestamp("unrecognised") == "Unknown"
    assert logs.timestamp("2026-11-02T10:00:00Z event") == "2026-11-02T10:00:00Z"


def test_accounting_folding_nas_identity_staleness_and_wraps():
    now = 1_800_000_000
    records = logs.accounting_records(
        detail("Start", now - 60)
        + detail(
            "Interim-Update",
            now - 20,
            extra=(
                "\tAcct-Session-Time = 40\n\tAcct-Input-Octets = 5\n"
                '\tAcct-Input-Gigawords = 1\n\tUser-Password = "SECRET"\n'
            ),
        )
        + detail("Stop", now - 10, extra="\tAcct-Session-Time = 50\n")
        + detail("Start", now - 2000, nas="192.0.2.9")
        + detail("Start", now - 5, session="two")
        + detail("Stop", now, session="partial").rstrip()
    )
    assert "SECRET" not in str(records)
    rows = logs.session_rows(records[::-1], now)
    assert [row["status"] for row in rows] == ["Active", "Ended", "Stale"]
    assert rows[1]["received"] == str((1 << 32) + 5)
    assert rows[1]["duration"] == "50"
    assert rows[1]["started"] == logs._utc(now - 60)
    assert rows[1]["ended"] == logs._utc(now - 10)
    reset = logs.session_rows(records + logs.accounting_records(detail("Start", now)), now)
    assert reset[0]["received"] == ""
    assert logs.session_rows([{"Timestamp": "1", "Acct-Status-Type": "Start"}], now) == []
    assert logs.session_rows(logs.accounting_records(detail("Start", 999999999999)), now) == []


def test_tail_bounded_and_rejects_special_files(tmp_path, monkeypatch):
    path = tmp_path / "log"
    path.write_text("discard-this-partial-line\nkept\n")
    monkeypatch.setattr(logs, "MAX_BYTES", 12)
    assert logs.tail(path) == "kept\n"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        logs.tail(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular"):
        logs.tail(fifo)
    monkeypatch.setattr(logs, "MAX_ROWS", 1)
    assert len(logs.dhcp_rows("DHCPACK on 192.0.2.2 to aa:bb\n" * 3)) == 1


@pytest.mark.parametrize(
    "factory,variable,endpoint",
    [
        (create_radius_agent, "RADIUS_AUTH_LOG_FILE", "logins"),
        (create_dhcp_agent, "DHCP_LOG_FILE", "leases"),
        (create_dns_agent, "DNS_UPDATE_LOG_FILE", "ddns"),
    ],
)
def test_agent_log_configuration_and_auth(factory, variable, endpoint, monkeypatch, tmp_path):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-token")
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    monkeypatch.delenv(variable, raising=False)
    client = factory().test_client()
    url = f"/logs/{endpoint}"
    assert client.get(url).status_code == 401
    headers = {"Authorization": "Bearer test-token"}
    assert client.get(url, headers=headers).json["status"] == "unavailable"
    path = tmp_path / "log"
    monkeypatch.setenv(variable, str(path))
    client = factory().test_client()
    assert client.get(url, headers=headers).json["status"] == "unavailable"
    path.write_text("")
    result = client.get(url, headers=headers)
    assert result.status_code == 200 and result.json["status"] == "available"
    assert result.json["rows"] == []
    assert client.post(url, headers=headers).status_code in {403, 405}
    monkeypatch.setenv(variable, "../bad")
    with pytest.raises(ValueError):
        factory()


def test_accounting_agent_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-token")
    monkeypatch.setenv("RADIUS_ACCOUNTING_DIR", str(tmp_path))
    nas = tmp_path / "192.0.2.1"
    nas.mkdir()
    (nas / "detail-20261102").write_text(detail("Start", int(time.time())))
    (nas / "auth-detail-20261102").write_text("SECRET")
    client = create_radius_agent().test_client()
    result = client.get("/logs/sessions", headers={"Authorization": "Bearer test-token"}).json
    assert result["status"] == "available"
    assert result["rows"][0]["user"] == "alice"
    for index in range(257):
        (nas / f"detail-{index}").touch()
    assert (
        client.get("/logs/sessions", headers={"Authorization": "Bearer test-token"}).json["status"]
        == "unavailable"
    )


@pytest.mark.parametrize(
    "page,resource,service",
    [
        ("radius-logins", "logins", "radius"),
        ("dhcp-leases", "leases", "dhcp"),
        ("ddns-changes", "ddns", "dns"),
        ("radius-sessions", "sessions", "radius"),
    ],
)
def test_pages_authorization_exact_sources_and_activity_isolation(
    page, resource, service, tmp_path, monkeypatch
):
    app = make_app(tmp_path)
    app.extensions["netadmin_dns"] = AgentDnsService(AgentClient("https://dns", ""))
    calls = []

    def get(self, path):
        calls.append((self, path))
        return {
            "status": "available",
            "reason": "Recent records",
            "rows": [
                {
                    "user": "<script>synthetic-login</script>",
                    "action": "synthetic-lease",
                    "name": "synthetic-ddns",
                    "status": "Active",
                }
            ],
        }

    monkeypatch.setattr(AgentClient, "get", get)
    client = app.test_client()
    assert client.get(f"/logs/{page}").status_code == 302
    store = app.extensions["netadmin_store"]
    token = store.create_session("standard", "standard", 3600)
    client.set_cookie("netadmin_session", token)
    assert client.get(f"/logs/{page}").status_code == 403
    assert not calls
    token = store.create_session("root", "admin", 3600)
    client.set_cookie("netadmin_session", token)
    response = client.get(f"/logs/{page}")
    assert response.status_code == 200
    assert b'data-table-filter="service-log"' in response.data
    assert b"<script>synthetic-login" not in response.data
    expected = app.extensions[f"netadmin_{service}"]
    assert calls == [(expected.client if service == "dns" else expected, f"logs/{resource}")]
    for url in ("/", "/audit"):
        response = client.get(url)
        assert b"synthetic-login" not in response.data
        assert b"synthetic-lease" not in response.data
        assert b"synthetic-ddns" not in response.data
    assert len(calls) == 1
    assert client.get("/logs/unknown").status_code == 404


@pytest.mark.parametrize("payload", [None, {}, {"status": "available", "rows": [1]}])
def test_malformed_agent_response_is_unavailable(tmp_path, monkeypatch, payload):
    app = make_app(tmp_path)
    monkeypatch.setattr(AgentClient, "get", lambda *args: payload)
    client = app.test_client()
    client.set_cookie(
        "netadmin_session", app.extensions["netadmin_store"].create_session("root", "admin", 3600)
    )
    assert b"Logs are unavailable" in client.get("/logs/radius-logins").data


def test_legacy_agent_and_direct_dns_unavailable(tmp_path, monkeypatch):
    app = make_app(tmp_path)

    def missing(*args):
        response = httpx.Response(404, request=httpx.Request("GET", "https://agent/logs/logins"))
        response.raise_for_status()

    monkeypatch.setattr(AgentClient, "get", missing)
    client = app.test_client()
    client.set_cookie(
        "netadmin_session", app.extensions["netadmin_store"].create_session("root", "admin", 3600)
    )
    assert b"Logs are unavailable" in client.get("/logs/radius-logins").data
    assert b"DNS agent connection" in client.get("/logs/ddns-changes").data


def test_accounting_restart_and_missing_duration_preserve_start():
    records = logs.accounting_records(
        detail("Start", 1000)
        + detail("Interim-Update", 1100)
        + detail("Accounting-On", 1200, session="")
    )
    row = logs.session_rows(records, 1250)[0]
    assert row["status"] == "Stale"
    assert row["started"] == logs._utc(1000)


def test_disabled_service_and_empty_source(tmp_path, monkeypatch):
    from dataclasses import replace

    app = make_app(tmp_path)
    client = app.test_client()
    client.set_cookie(
        "netadmin_session", app.extensions["netadmin_store"].create_session("root", "admin", 3600)
    )
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], radius_enabled=False
    )
    assert b"Service is disabled" in client.get("/logs/radius-logins").data
    monkeypatch.setattr(
        AgentClient,
        "get",
        lambda *args: {"status": "available", "rows": [], "reason": "Retained records"},
    )
    assert b"No records found" in client.get("/logs/dhcp-leases").data


def test_agent_response_cannot_override_template_arguments(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    monkeypatch.setattr(
        AgentClient,
        "get",
        lambda *args: {
            "status": "available",
            "rows": [],
            "reason": "Bounded records",
            "title": "unexpected",
            "columns": None,
        },
    )
    client = app.test_client()
    client.set_cookie(
        "netadmin_session", app.extensions["netadmin_store"].create_session("root", "admin", 3600)
    )
    response = client.get("/logs/radius-logins")
    assert response.status_code == 200
    assert b"RADIUS Login Log" in response.data
    assert b"unexpected" not in response.data


def test_accounting_source_permission_error_is_not_empty(monkeypatch, tmp_path):
    from netadmin.agents import service_logs as agent_logs

    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-token")
    monkeypatch.setenv("RADIUS_ACCOUNTING_DIR", str(tmp_path))
    client = create_radius_agent().test_client()

    def denied(*args):
        raise PermissionError("synthetic denied path")

    monkeypatch.setattr(agent_logs.os, "scandir", denied)
    response = client.get("/logs/sessions", headers={"Authorization": "Bearer test-token"})
    assert response.json["status"] == "unavailable"
    assert "synthetic denied path" not in response.text
