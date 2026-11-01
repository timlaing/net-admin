"""Multiple zones and DHCP pools remain independently addressable in the UI."""

from types import SimpleNamespace

from netadmin.services.dns import DnsZone
from tests.test_app import make_app


def admin_client(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    token = app.extensions["netadmin_store"].create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", token)
    return app, client


def test_multiple_dns_zones_can_be_selected_independently(tmp_path):
    app, client = admin_client(tmp_path)
    selected = []
    app.extensions["netadmin_dns"] = SimpleNamespace(
        zones=lambda: [DnsZone("example.net", "", True), DnsZone("other.net", "", True)],
        records=lambda zone: selected.append(zone) or [],
    )
    for zone in ("example.net", "other.net"):
        response = client.get("/dns", query_string={"zone": zone})
        assert response.status_code == 200
        assert f'value="{zone}" selected' in response.text
        assert "example.net" in response.text
        assert "other.net" in response.text
    assert selected == ["example.net", "other.net"]


def test_multiple_dhcp_subnets_and_ranges_update_independently(tmp_path):
    app, client = admin_client(tmp_path)
    changes = []
    subnets = [
        {
            "network": "192.0.2.0",
            "netmask": "255.255.255.0",
            "ranges": [("192.0.2.10", "192.0.2.20"), ("192.0.2.30", "192.0.2.40")],
            "options": {},
        },
        {
            "network": "198.51.100.0",
            "netmask": "255.255.255.0",
            "ranges": [("198.51.100.10", "198.51.100.20")],
            "options": {},
        },
    ]
    app.extensions["netadmin_dhcp"] = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: subnets if path == "configuration" else [],
        post=lambda path, payload: changes.append((path, payload)),
    )
    page = client.get("/dhcp")
    assert page.status_code == 200
    assert 'id="subnets"' in page.text
    assert 'class="btn btn-sm btn-outline-primary" aria-label="Edit subnet 192.0.2.0"' in page.text
    page = client.get("/dhcp/subnets/192.0.2.0")
    assert "192.0.2.10-192.0.2.20" in page.text
    assert "192.0.2.30-192.0.2.40" in page.text
    page = client.get("/dhcp/subnets/198.51.100.0")
    assert "198.51.100.10-198.51.100.20" in page.text
    response = client.post(
        "/dhcp/configuration",
        data={
            "network": "198.51.100.0",
            "ranges": "198.51.100.50-198.51.100.60",
            "options": "",
        },
    )
    assert response.status_code == 302
    assert changes == [
        (
            "configuration",
            {
                "network": "198.51.100.0",
                "ranges": [["198.51.100.50", "198.51.100.60"]],
                "options": {},
            },
        )
    ]


def test_subnet_create_and_remove_controls_use_agent(tmp_path):
    app, client = admin_client(tmp_path)
    calls = []
    app.extensions["netadmin_dhcp"] = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: [],
        post=lambda path, payload: calls.append((path, payload)),
    )
    page = client.get("/dhcp")
    assert page.status_code == 200
    assert "Create subnet" in page.text
    assert client.post("/dhcp/subnets", data={"cidr": "192.0.2.0/24"}).status_code == 302
    assert client.post("/dhcp/subnets/delete", data={"network": "192.0.2.0"}).status_code == 302
    assert calls == [
        ("subnets", {"cidr": "192.0.2.0/24"}),
        ("subnets/delete", {"network": "192.0.2.0"}),
    ]
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/dhcp/subnets", data={"cidr": "198.51.100.0/24"}).status_code == 400


def test_zone_failure_keeps_selection_and_offers_explicit_snapshot(tmp_path, monkeypatch):
    import httpx

    from netadmin.services.agents import AgentClient
    from netadmin.services.dns import AgentDnsService

    app, client = admin_client(tmp_path)
    remote = AgentClient("https://synthetic", "synthetic")
    service = AgentDnsService(remote)
    app.extensions["netadmin_dns"] = service
    from dataclasses import replace

    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], dns_use_agent=True
    )

    def get(path):
        if path == "capabilities":
            return {"read_only": True}
        if path == "zones":
            return [{"name": "example.net", "file": "zone", "dynamic": True}]
        if "source=file" in path:
            return [{"name": "snapshot-host", "ttl": 300, "record_type": "A", "value": "192.0.2.1"}]
        request = httpx.Request("GET", "https://synthetic/records")
        response = httpx.Response(502, request=request)
        raise httpx.HTTPStatusError("private backend details", request=request, response=response)

    monkeypatch.setattr(remote, "get", get)
    response = client.get("/dns?zone=example.net")
    assert response.status_code == 200
    assert "authenticated zone transfers (AXFR)" in response.text
    assert "Read local zone snapshot" in response.text
    assert "private backend details" not in response.text
    assert 'value="example.net" selected' in response.text
    response = client.get("/dns?zone=example.net&source=file")
    assert response.status_code == 200
    assert "snapshot-host" in response.text
    assert "not a live zone transfer" in response.text
    assert "This agent is read-only" in response.text
    assert 'method="post"' not in response.text.split("<main", 1)[-1].split("</main>", 1)[0]
    assert "Add or replace record" not in response.text


def test_subnet_detail_validates_and_blocks_read_only_writes(tmp_path):
    app, client = admin_client(tmp_path)
    changes = []
    subnet = {"network": "192.0.2.0", "netmask": "255.255.255.0", "ranges": [], "options": {}}
    remote = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: [subnet] if path == "configuration" else [],
        post=lambda path, payload: changes.append((path, payload)),
    )
    app.extensions["netadmin_dhcp"] = remote
    path = "/dhcp/subnets/192.0.2.0"
    data = {
        "network": "198.51.100.0",
        "ranges": "192.0.2.10-192.0.2.20",
        "options": "routers=192.0.2.1",
    }
    assert client.post(path, data=data).status_code == 302
    assert changes[0][1]["network"] == "192.0.2.0"
    assert changes[0][1]["options"] == {"routers": "192.0.2.1"}
    data["options"] = "invalid option"
    response = client.post(path, data=data)
    assert response.status_code == 422
    assert "invalid option" in response.text
    assert len(changes) == 1
    remote.read_only = lambda: True
    page = client.get("/dhcp")
    assert "Create subnet" not in page.text
    assert "Add or update reservation" not in page.text
    page = client.get(path)
    assert "Remove subnet" not in page.text
    assert "Update subnet" not in page.text
    assert client.post(path, data=data).status_code == 403
    assert len(changes) == 1
    assert client.get("/dhcp/subnets/203.0.113.0").status_code == 404


def test_structured_subnet_editor_keeps_fallback_and_supports_clearing(tmp_path):
    app, client = admin_client(tmp_path)
    changes = []
    subnet = {
        "network": "192.0.2.0",
        "netmask": "255.255.255.0",
        "ranges": [["192.0.2.10", "192.0.2.20"]],
        "options": {"domain-name": '"example.net"', "custom": '"<sample>"'},
    }
    app.extensions["netadmin_dhcp"] = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: [subnet],
        post=lambda path, payload: changes.append((path, payload)),
    )
    path = "/dhcp/subnets/192.0.2.0"
    page = client.get(path)
    assert "data-subnet-editor" in page.text
    assert 'type="module"' in page.text
    assert 'name="ranges"' in page.text and 'name="options"' in page.text
    assert "<sample>" not in page.text
    response = client.post(path, data={"network": "192.0.2.0", "ranges": "", "options": ""})
    assert response.status_code == 302
    assert changes == [("configuration", {"network": "192.0.2.0", "ranges": [], "options": {}})]


def test_read_only_radius_hides_all_write_controls(tmp_path):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: True,
        get=lambda path: {
            "users": [{"username": "reader", "source": "netadmin"}],
            "clients": [{"name": "gateway", "source": "clients.conf", "address": "192.0.2.1"}],
            "migration": {"count": 1},
        }[path],
    )
    page = client.get("/radius")
    assert page.status_code == 200
    assert "gateway" in page.text
    assert "reader" in page.text
    for control in (
        "Add or update",
        "Migrate users",
        "Delete client",
        "Delete user",
        "data-edit-client",
    ):
        assert control not in page.text
