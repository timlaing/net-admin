"""All deletion forms retain authorization/CSRF and acknowledge mutations explicitly."""

import re
import uuid
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from netadmin.services.dns import AgentDnsService, DnsRecord, DnsZone
from tests.test_ingress import HEADERS, PREFIX
from tests.test_ingress import make_app as ingress_app
from tests.test_multi_service_ui import admin_client

JSON = {"Accept": "application/json"}
CASES = [
    (
        "/dns/records/delete",
        {"zone": "example.test", "name": "host", "record_type": "A", "value": "192.0.2.9"},
        "/dns?zone=example.test",
    ),
    ("/dns/zones/delete", {"zone": "example.test"}, "/dns"),
    ("/dhcp/reservations/delete", {"name": "host"}, "/dhcp"),
    ("/dhcp/subnets/delete", {"network": "192.0.2.0"}, "/dhcp"),
    ("/radius/users/delete", {"username": "user"}, "/radius"),
    ("/radius/clients/delete", {"name": "client"}, "/radius"),
]


@pytest.fixture
def deletion_client(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []
    remote = SimpleNamespace(post=lambda *args: calls.append(args))
    app.extensions.update(
        netadmin_dns=SimpleNamespace(
            delete=lambda *args: calls.append(args),
            zone_agent=remote,
            zones=lambda: [DnsZone("example.test", "", True)],
            records=lambda _zone: [
                DnsRecord("@", 300, "SOA", "ns.example.test. admin.example.test. 1 2 3 4 5"),
                DnsRecord("@", 300, "NS", "ns.example.test."),
                DnsRecord("host", 300, "A", "192.0.2.9"),
            ],
        ),
        netadmin_dhcp=remote,
        netadmin_radius=remote,
    )
    return app, client, calls


@pytest.mark.parametrize(("path", "payload", "destination"), CASES)
def test_deletions_return_explicit_json_without_redirect_or_flash(
    deletion_client, path, payload, destination
):
    _app, client, calls = deletion_client
    response = client.post(path, data=payload, headers=JSON)
    assert response.status_code == 200
    assert response.json == {"deleted": True, "refresh_url": destination}
    assert len(calls) == 1
    assert "Location" not in response.headers
    with client.session_transaction() as session:
        assert not session.get("_flashes")


@pytest.mark.parametrize(("path", "payload", "destination"), CASES)
def test_native_deletions_keep_redirect_fallback(deletion_client, path, payload, destination):
    _app, client, calls = deletion_client
    response = client.post(path, data=payload)
    assert response.status_code == 302
    assert response.location == destination
    assert len(calls) == 1


@pytest.mark.parametrize(("path", "payload", "_destination"), CASES)
def test_every_delete_requires_admin_and_csrf(deletion_client, path, payload, _destination):
    app, client, calls = deletion_client
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post(path, data=payload, headers=JSON).status_code == 400
    page = client.get("/login")
    csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text)[1]
    standard = app.extensions["netadmin_store"].create_session("standard", "standard", 60)
    client.set_cookie("netadmin_session", standard)
    assert client.post(path, data={**payload, "csrf_token": csrf}, headers=JSON).status_code == 403
    client.delete_cookie("netadmin_session")
    assert client.post(path, data={**payload, "csrf_token": csrf}, headers=JSON).status_code == 302
    assert calls == []


def test_async_delete_sends_the_existing_csrf_form_token(deletion_client):
    app, client, calls = deletion_client
    app.config["WTF_CSRF_ENABLED"] = True
    page = client.get("/login")
    csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text)[1]
    response = client.post(CASES[0][0], data={**CASES[0][1], "csrf_token": csrf}, headers=JSON)
    assert response.status_code == 200
    assert response.json["deleted"] is True
    assert calls == [("example.test", "host", "A", "192.0.2.9")]


def test_ajax_refresh_destination_keeps_verified_ingress_prefix(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    app = ingress_app(tmp_path)
    calls = []
    app.extensions["netadmin_dns"] = SimpleNamespace(delete=lambda *args: calls.append(args))
    client = app.test_client()
    token = app.extensions["netadmin_store"].create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", token)
    response = client.post(CASES[0][0], data=CASES[0][1], headers={**HEADERS, **JSON})
    assert response.status_code == 200
    assert response.json["refresh_url"] == PREFIX + "/dns?zone=example.test"
    assert len(calls) == 1


def test_dns_async_delete_requires_exact_value_and_rejects_protected_types(deletion_client):
    _app, client, calls = deletion_client
    payload = CASES[0][1]
    for changed in (
        {"value": ""},
        {"zone": ""},
        {"name": ""},
        {"record_type": ""},
        {"name": "x" * 254},
    ):
        response = client.post(CASES[0][0], data={**payload, **changed}, headers=JSON)
        assert response.status_code == 400
        assert response.json["deleted"] is False
    for kind in ("SOA", "NS", "ANY", "AXFR", "IXFR", "OPT", "TSIG", "soa"):
        assert (
            client.post(
                CASES[0][0], data={**payload, "record_type": kind}, headers=JSON
            ).status_code
            == 400
        )
    assert calls == []
    assert client.post(CASES[0][0], data={**payload, "record_type": "NS"}).status_code == 302
    assert client.post(CASES[0][0], data={"zone": "example.test"}).status_code == 302
    assert calls == []


@pytest.mark.parametrize(("path", "payload", "_destination"), CASES)
def test_backend_rejection_is_not_acknowledged_or_exposed(
    deletion_client, path, payload, _destination
):
    app, client, _calls = deletion_client

    def reject(*_args):
        raise httpx.ReadTimeout("synthetic-private-server-detail")

    app.extensions["netadmin_dns"].delete = reject
    app.extensions["netadmin_dns"].zone_agent.post = reject
    response = client.post(path, data=payload, headers=JSON)
    assert response.status_code == 502
    assert response.json["deleted"] is False
    assert "synthetic-private-server-detail" not in response.text


def test_dns_table_only_enables_selection_for_deletable_records(deletion_client):
    _app, client, _calls = deletion_client
    page = client.get("/dns?zone=example.test")
    assert page.status_code == 200
    assert page.text.count("data-delete-row ") == 1
    assert page.text.count("data-row-delete ") == 1
    assert 'data-sort="none"' in page.text
    assert "Delete selected" in page.text
    assert "table_delete.js" in page.text


def test_read_only_dns_has_no_delete_forms_or_selection_controls(deletion_client):
    app, client, calls = deletion_client
    remote = SimpleNamespace(
        get=lambda path: (
            [{"name": "example.test", "file": "zone", "dynamic": True}]
            if path == "zones"
            else [{"name": "host", "ttl": 300, "record_type": "A", "value": "192.0.2.9"}]
        ),
        read_only=lambda: True,
    )
    app.extensions["netadmin_dns"] = AgentDnsService(remote)
    response = client.get("/dns?zone=example.test")
    assert response.status_code == 200
    assert "This agent is read-only" in response.text
    assert "data-delete-row" not in response.text
    assert "data-row-delete" not in response.text
    assert "Delete selected" not in response.text
    assert calls == []


def test_authority_delete_acknowledges_without_exposing_private_result(
    deletion_client, monkeypatch
):
    app, client, calls = deletion_client
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], ca_enabled=True
    )
    remote = SimpleNamespace(
        post=lambda *args, **kwargs: calls.append((args, kwargs)) or {"private": "not-returned"}
    )
    monkeypatch.setattr("netadmin.ca_authorities_web.client", lambda: remote)
    payload = {
        "request_id": uuid.uuid4().hex,
        "authority_id": uuid.uuid4().hex,
        "confirmation": "DELETE CA",
        "confirm": "yes",
    }
    response = client.post("/certificates/authorities/delete", data=payload, headers=JSON)
    assert response.status_code == 200
    assert response.json == {"deleted": True, "refresh_url": "/certificates/authorities"}
    assert "not-returned" not in response.text
    assert calls[0][0] == (
        "authorities/delete",
        {key: value for key, value in payload.items() if key != "confirm"},
    )
    assert calls[0][1] == {"timeout": 100}
    calls.clear()
    assert (
        client.post(
            "/certificates/authorities/delete", data={**payload, "confirm": "no"}, headers=JSON
        ).status_code
        == 400
    )
    assert calls == []
