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
        assert "example.net" in response.text and "other.net" in response.text
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
        get=lambda path: subnets if path == "configuration" else [],
        post=lambda path, payload: changes.append((path, payload)),
    )
    page = client.get("/dhcp")
    assert page.status_code == 200
    assert "192.0.2.10-192.0.2.20" in page.text
    assert "192.0.2.30-192.0.2.40" in page.text
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
        get=lambda path: [],
        post=lambda path, payload: calls.append((path, payload)),
    )
    page = client.get("/dhcp")
    assert page.status_code == 200 and "Create subnet" in page.text
    assert client.post("/dhcp/subnets", data={"cidr": "192.0.2.0/24"}).status_code == 302
    assert client.post("/dhcp/subnets/delete", data={"network": "192.0.2.0"}).status_code == 302
    assert calls == [
        ("subnets", {"cidr": "192.0.2.0/24"}),
        ("subnets/delete", {"network": "192.0.2.0"}),
    ]
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/dhcp/subnets", data={"cidr": "198.51.100.0/24"}).status_code == 400
