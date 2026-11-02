"""Administrative forwarding and self-service account/session contracts."""

from types import SimpleNamespace

import httpx

from netadmin.services.dns import AgentDnsService, DnsZone
from tests.test_multi_service_ui import admin_client


def test_dns_mutations_forward_exact_identity_and_write_audit(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []
    agent = SimpleNamespace(post=lambda path, payload: calls.append((path, payload)))
    bind = SimpleNamespace(
        zone_agent=agent,
        upsert=lambda *args: calls.append(("upsert", args)),
        delete=lambda *args: calls.append(("delete", args)),
        add_host=lambda *args: calls.append(("add_host", args)),
        zones=lambda: [DnsZone("example.test", "", True)],
        records=lambda _zone: [],
    )
    app.extensions["netadmin_dns"] = bind
    valid = {
        "name": "example.test",
        "content": (
            "$ORIGIN example.test.\n@ 300 IN SOA ns.example.test. "
            "hostmaster.example.test. 1 3600 600 86400 300\n"
        ),
    }
    assert client.post("/dns/zones", data=valid).status_code == 302
    assert calls[-1] == ("zones", valid)
    assert client.post("/dns/zones/delete", data={"zone": "example.test"}).status_code == 302
    assert calls[-1] == ("zones/delete", {"name": "example.test"})
    record = {
        "zone": "example.test.",
        "name": "host",
        "record_type": "A",
        "ttl": "600",
        "value": "192.0.2.9",
    }
    assert client.post("/dns/records", data=record).status_code == 302
    assert calls[-1] == ("upsert", ("example.test", "host", "A", 600, "192.0.2.9"))
    assert client.post("/dns/records/delete", data=record).status_code == 302
    assert calls[-1] == ("delete", ("example.test.", "host", "A", "192.0.2.9"))
    assert (
        client.post(
            "/dns/rpi",
            data={
                "hostname": "pi",
                "address": "192.0.2.9",
                "forward_zone": "example.test",
                "reverse_zone": "2.0.192.in-addr.arpa",
                "ttl": "600",
            },
        ).status_code
        == 302
    )
    assert calls[-1] == (
        "add_host",
        ("pi", "192.0.2.9", "example.test", "2.0.192.in-addr.arpa", 600),
    )
    audit = client.get("/audit").data
    for action in (
        b"dns.zone.create",
        b"dns.zone.delete",
        b"dns.upsert",
        b"dns.delete",
        b"dns.rpi.create",
    ):
        assert action in audit
    count = len(calls)
    assert client.post("/dns/records", data={**record, "ttl": "not-a-number"}).status_code == 302
    assert client.post("/dns/zones", data={"name": ""}).status_code == 302
    assert len(calls) == count
    assert (
        b"Select a configured authoritative zone" in client.get("/dns?zone=unconfigured.test").data
    )
    bind.zone_agent = None
    assert client.post("/dns/zones", data=valid).status_code == 302
    assert client.post("/dns/zones/delete", data={"zone": "example.test"}).status_code == 302
    assert len(calls) == count


def test_dns_file_snapshot_and_backend_error_stay_on_expected_boundary(tmp_path):
    app, client = admin_client(tmp_path)
    paths = []

    def get(path):
        paths.append(path)
        if path == "zones":
            return [{"name": "example.test", "file": "zone", "dynamic": True}]
        return [{"name": "host", "ttl": 60, "record_type": "A", "value": "192.0.2.9"}]

    app.extensions["netadmin_dns"] = AgentDnsService(
        SimpleNamespace(get=get, read_only=lambda: False)
    )
    response = client.get("/dns?zone=example.test&source=file")
    assert response.status_code == 200
    assert b"192.0.2.9" in response.data
    assert "records?zone=example.test&source=file" in paths
    app.extensions["netadmin_dns"] = SimpleNamespace(
        zone_agent=SimpleNamespace(
            post=lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic-backend-diagnostic"))
        )
    )
    failure = client.post("/dns/zones/delete", data={"zone": "example.test"})
    assert failure.status_code == 502
    assert b"synthetic-backend-diagnostic" not in failure.data


def test_dhcp_reservation_and_delete_forward_to_agent(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []
    app.extensions["netadmin_dhcp"] = SimpleNamespace(
        post=lambda path, payload: calls.append((path, payload))
    )
    payload = {"name": "node", "mac": "aa:bb:cc:dd:ee:ff", "address": "192.0.2.9"}
    assert client.post("/dhcp", data=payload).status_code == 302
    assert calls[-1] == ("reservations", payload)
    assert client.post("/dhcp/reservations/delete", data={"name": "node"}).status_code == 302
    assert calls[-1] == ("reservations/delete", {"name": "node"})
    assert b"dhcp.reservation.upsert" in client.get("/audit").data
    count = len(calls)
    assert (
        client.post(
            "/dhcp/configuration",
            data={"network": "192.0.2.0", "ranges": "not-a-range-with-extra-dash", "options": ""},
        ).status_code
        == 302
    )
    assert len(calls) == count


def test_radius_client_user_and_migration_forward_to_selected_agent(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []

    def post(path, payload, **kwargs):
        calls.append((path, payload, kwargs))
        return {"count": 3}

    app.extensions["netadmin_radius"] = SimpleNamespace(post=post)
    payload = {
        "name": "access-point",
        "address": "192.0.2.10",
        "shortname": "ap",
        "secret": "synthetic-shared-secret",
    }
    assert client.post("/radius/clients", data=payload).status_code == 302
    assert calls[-1] == ("clients", payload, {})
    assert client.post("/radius/clients/delete", data={"name": "access-point"}).status_code == 302
    assert calls[-1] == ("clients/delete", {"name": "access-point"}, {})
    assert client.post("/radius/users/delete", data={"username": "ordinary"}).status_code == 302
    assert calls[-1] == ("users/delete", {"username": "ordinary"}, {})
    assert client.post("/radius/migrate").status_code == 302
    assert calls[-1] == ("migration", {}, {"timeout": 80})
    assert b"radius.users.migrate" in client.get("/audit").data
    count = len(calls)
    assert client.post("/radius/clients", data={"name": ""}).status_code == 302
    assert len(calls) == count


def test_radius_password_change_uses_current_identity_and_invalidates_only_its_sessions(
    tmp_path, monkeypatch
):
    app, client = admin_client(tmp_path)
    store = app.extensions["netadmin_store"]
    token = store.create_session("ordinary", "standard", 60)
    second = store.create_session("ordinary", "standard", 60)
    other = store.create_session("other", "standard", 60)
    client.set_cookie("netadmin_session", token)
    calls = []
    app.extensions["netadmin_radius"] = SimpleNamespace(
        post=lambda path, payload: calls.append((path, payload))
    )
    assert b"Change password" in client.get("/password").data
    payload = {
        "username": "victim",
        "current_password": "old-synthetic-password",
        "new_password": "new-synthetic-password",
        "confirm_password": "new-synthetic-password",
    }
    monkeypatch.setattr("netadmin.app.authenticate_radius", lambda *_args: None)
    failed = client.post("/password", data=payload)
    assert b"Current password is incorrect" in failed.data
    assert not calls
    assert store.get_session(token)
    monkeypatch.setattr("netadmin.app.authenticate_radius", lambda *_args: "standard")
    success = client.post("/password", data=payload)
    assert success.status_code == 302
    assert "/login" in success.location
    assert calls == [
        ("users/password", {"username": "ordinary", "password": "new-synthetic-password"})
    ]
    assert store.get_session(token) is None
    assert store.get_session(second) is None
    assert store.get_session(other) is not None
    assert "netadmin_session=;" in success.headers["Set-Cookie"]


def test_password_attempt_rate_limit_does_not_contact_mutating_agent(tmp_path, monkeypatch):
    app, client = admin_client(tmp_path)
    store = app.extensions["netadmin_store"]
    token = store.create_session("ordinary", "standard", 60)
    client.set_cookie("netadmin_session", token)
    calls = []
    app.extensions["netadmin_radius"] = SimpleNamespace(post=lambda *args: calls.append(args))
    monkeypatch.setattr("netadmin.app.authenticate_radius", lambda *_args: None)
    payload = {
        "current_password": "wrong",
        "new_password": "new-synthetic-password",
        "confirm_password": "new-synthetic-password",
    }
    for _ in range(5):
        assert client.post("/password", data=payload).status_code == 200
    response = client.post("/password", data=payload)
    assert response.status_code == 429
    assert b"Too many password-change attempts" in response.data
    assert not calls
    root = store.create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", root)
    assert client.post("/password", data=payload).status_code == 302


def test_login_rate_limit_and_logout_session_revocation(tmp_path, monkeypatch):
    app, client = admin_client(tmp_path)
    client.delete_cookie("netadmin_session")
    monkeypatch.setattr("netadmin.app.authenticate_radius", lambda *_args: None)
    for _ in range(5):
        assert (
            client.post("/login", data={"username": "throttled", "password": "wrong"}).status_code
            == 200
        )
    assert (
        client.post("/login", data={"username": "throttled", "password": "wrong"}).status_code
        == 429
    )
    store = app.extensions["netadmin_store"]
    token = store.create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", token)
    response = client.post("/logout")
    assert response.status_code == 302
    assert store.get_session(token) is None
    assert "netadmin_session=;" in response.headers["Set-Cookie"]


def test_radius_mutation_conflicts_and_unexpected_http_errors_are_distinct(tmp_path):
    app, client = admin_client(tmp_path)
    status = [409]

    def fail(*_args, **_kwargs):
        response = httpx.Response(
            status[0], request=httpx.Request("POST", "https://radius.test/users")
        )
        response.raise_for_status()

    app.extensions["netadmin_radius"] = SimpleNamespace(post=fail, get=fail)
    data = {"username": "ordinary", "role": "standard", "password": ""}
    assert client.post("/radius", data=data).status_code == 302
    status[0] = 503
    assert client.post("/radius", data=data).status_code == 502


def test_dhcp_export_and_radius_user_success_preserve_payloads(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []
    snapshot = {"Dhcp4": {"subnet4": []}}
    app.extensions["netadmin_dhcp"] = SimpleNamespace(get=lambda path: snapshot)
    assert client.get("/dhcp/export/kea").json == snapshot
    app.extensions["netadmin_radius"] = SimpleNamespace(
        post=lambda path, payload: calls.append((path, payload))
    )
    assert (
        client.post(
            "/radius", data={"username": "ordinary", "role": "standard", "password": ""}
        ).status_code
        == 302
    )
    assert calls == [
        ("users", {"username": "ordinary", "password": "", "role": "standard", "disabled": False})
    ]
    assert b"radius.user.upsert" in client.get("/audit").data


def test_radius_certificate_http_failures_are_bounded_and_audited(tmp_path):
    app, client = admin_client(tmp_path)

    def fail(*_args, **_kwargs):
        raise httpx.ConnectError("synthetic-private-diagnostic")

    app.extensions["netadmin_radius"] = SimpleNamespace(
        get=fail, post=fail, read_only=lambda: False
    )
    response = client.get("/radius/certificates")
    assert response.status_code == 200
    assert b"Certificate details are unavailable" in response.data
    assert b"synthetic-private-diagnostic" not in response.data
    assert client.post("/radius/certificates", data={"action": "invalid"}).status_code == 400
    response = client.post(
        "/radius/certificates", data={"action": "renew-server", "confirm": "yes"}
    )
    assert response.status_code == 502
    assert b"synthetic-private-diagnostic" not in response.data
    assert b"radius.certificate.renew-server" in client.get("/audit").data


def test_radius_authentication_conflicts_and_read_only_guards(tmp_path):
    app, client = admin_client(tmp_path)
    status = [409]
    calls = []

    def fail(path, payload, **_kwargs):
        calls.append((path, payload))
        httpx.Response(
            status[0], request=httpx.Request("POST", "https://radius.test/authentication")
        ).raise_for_status()

    agent = SimpleNamespace(post=fail, read_only=lambda: False)
    app.extensions["netadmin_radius"] = agent
    payload = {"confirm": "yes", "enabled": "pap", "preferred": "pap", "revision": "old"}
    assert client.post("/radius/authentication", data=payload).status_code == 302
    assert calls[-1] == (
        "authentication",
        {"enabled": ["pap"], "preferred": "pap", "revision": "old"},
    )
    status[0] = 503
    assert client.post("/radius/authentication", data=payload).status_code == 502
    agent.read_only = lambda: True
    count = len(calls)
    assert client.post("/radius/authentication", data=payload).status_code == 403
    assert len(calls) == count
