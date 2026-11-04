"""Authenticated endpoint tests for both privileged agents."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from netadmin.agents.dhcp import create_dhcp_agent, parse_reservations
from netadmin.agents.radius import create_radius_agent

AUTH = {"Authorization": "Bearer test-agent-token"}


def test_dhcp_agent_workflow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = tmp_path / "dhcpd.conf"
    managed = tmp_path / "netadmin-reservations.conf"
    leases = tmp_path / "dhcpd.leases"
    config.write_text(
        f'''subnet 192.0.2.0 netmask 255.255.255.0 {{
  range 192.0.2.10 192.0.2.20;
  option routers 192.0.2.1;
}}
include "{managed}";
'''
    )
    managed.write_text("# managed\n")
    leases.write_text(
        "lease 192.0.2.10 { binding state active; hardware ethernet aa:bb:cc:dd:ee:ff; }"
    )
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(config))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(managed))
    monkeypatch.setenv("DHCP_LEASES_FILE", str(leases))
    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", lambda *args, **kwargs: None)
    client = create_dhcp_agent().test_client()
    assert client.get("/health").status_code == 401
    assert client.get("/health", headers=AUTH).json == {"status": "ok", "backend": "isc"}
    assert client.get("/leases", headers=AUTH).get_json()[0]["state"] == "active"
    response = client.post(
        "/reservations",
        headers=AUTH,
        json={"name": "pi", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.5"},
    )
    assert response.status_code == 200
    assert client.get("/reservations", headers=AUTH).get_json()[0]["name"] == "pi"
    response = client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [["192.0.2.30", "192.0.2.40"]],
            "options": {"routers": "192.0.2.254"},
        },
    )
    assert response.status_code == 200
    assert client.get("/export/kea", headers=AUTH).get_json()["Dhcp4"]["subnet4"]
    assert client.post("/reservations/delete", headers=AUTH, json={"name": "pi"}).status_code == 200


def test_dhcp_agent_kea_workflow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = tmp_path / "kea4.conf"
    managed = tmp_path / "netadmin-reservations.json"
    leases = tmp_path / "dhcp4.leases"
    config.write_text(
        f'''{{
  "Dhcp4": {{
    "reservations-global": true,
    "subnet4": [
      {{
        "id": 1,
        "subnet": "192.0.2.0/24",
        "pools": [ {{ "pool": "192.0.2.10 - 192.0.2.20" }} ],
        "option-data": [ {{ "name": "routers", "data": "192.0.2.1" }} ]
      }}
    ],
    <?include "{managed}"?>
  }}
}}
'''
    )
    managed.write_text('"reservations": []\n')
    leases.write_text("192.0.2.10,aa:bb:cc:dd:ee:ff,,3600,1766798400,1,0,0,laptop,0,,\n")
    monkeypatch.setenv("DHCP_SERVER", "kea")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(config))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(managed))
    monkeypatch.setenv("DHCP_LEASES_FILE", str(leases))
    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", lambda *args, **kwargs: None)
    client = create_dhcp_agent().test_client()
    assert client.get("/health", headers=AUTH).json == {"status": "ok", "backend": "kea"}
    assert client.get("/leases", headers=AUTH).get_json()[0]["state"] == "active"
    response = client.post(
        "/reservations",
        headers=AUTH,
        json={"name": "pi", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.5"},
    )
    assert response.status_code == 200
    saved = parse_reservations(managed.read_text(encoding="utf-8"))
    assert saved == [{"name": "pi", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.5"}]
    assert client.get("/reservations", headers=AUTH).get_json()[0]["name"] == "pi"
    response = client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [["192.0.2.30", "192.0.2.40"]],
            "options": {"routers": "192.0.2.254"},
        },
    )
    assert response.status_code == 200
    updated = config.read_text(encoding="utf-8")
    assert "192.0.2.30 - 192.0.2.40" in updated
    assert "192.0.2.254" in updated
    snapshot = client.get("/export/kea", headers=AUTH).get_json()
    assert snapshot["Dhcp4"]["subnet4"][0]["id"] == 1
    response = client.post("/reservations/delete", headers=AUTH, json={"name": "pi"})
    assert response.status_code == 200
    assert parse_reservations(managed.read_text(encoding="utf-8")) == []


def test_radius_agent_workflow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    managed = tmp_path / "netadmin"
    authorize = tmp_path / "authorize"
    clients = tmp_path / "clients.conf"
    managed_clients = tmp_path / "netadmin-clients.conf"
    managed.write_text("# managed\n")
    authorize.write_text('alice Cleartext-Password := "legacy"\n\tFramed-Pool = "pool-parent"\n')
    clients.write_text("client existing {\n ipaddr = 192.0.2.1\n secret = hidden\n}\n")
    managed_clients.write_text("# managed\n")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("RADIUS_MANAGED_FILE", str(managed))
    monkeypatch.setenv("RADIUS_AUTHORIZE_FILE", str(authorize))
    monkeypatch.setenv("RADIUS_CLIENTS_FILE", str(clients))
    monkeypatch.setenv("RADIUS_MANAGED_CLIENTS_FILE", str(managed_clients))
    from netadmin.services.radius_users import PasswordHashes

    monkeypatch.setattr(
        "netadmin.agents.radius.hash_passwords",
        lambda value, **kwargs: PasswordHashes(f"$6${value}", "a" * 32),
    )
    monkeypatch.setattr(
        "netadmin.agents.radius.subprocess.run", lambda *args, **kwargs: SimpleNamespace()
    )
    client = create_radius_agent().test_client()
    assert client.get("/migration", headers=AUTH).get_json()["count"] == 1
    assert client.post("/migration", headers=AUTH, json={}).status_code == 200
    assert "alice" not in authorize.read_text()
    assert any(
        user["username"] == "alice" for user in client.get("/users", headers=AUTH).get_json()
    )
    response = client.post(
        "/users",
        headers=AUTH,
        json={"username": "bob", "password": "a-secure-password", "role": "standard"},
    )
    assert response.status_code == 200
    assert any(user["username"] == "bob" for user in client.get("/users", headers=AUTH).get_json())
    assert (
        client.post(
            "/clients",
            headers=AUTH,
            json={
                "name": "router",
                "address": "192.0.2.2",
                "shortname": "gateway",
                "secret": "long-private-secret",
            },
        ).status_code
        == 200
    )
    returned = client.get("/clients", headers=AUTH).get_json()
    assert all("secret" not in item for item in returned)
    assert client.post("/clients/delete", headers=AUTH, json={"name": "router"}).status_code == 200
    assert client.post("/users/delete", headers=AUTH, json={"username": "bob"}).status_code == 200


def test_dhcp_agent_rejects_bad_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(tmp_path / ".." / "dhcpd.conf"))
    with pytest.raises(ValueError, match="DHCP_MAIN_CONFIG"):
        create_dhcp_agent()


def test_dhcp_agent_rejects_bad_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_SERVER", "bogus")
    with pytest.raises(ValueError, match="DHCP_SERVER"):
        create_dhcp_agent()


def test_radius_agent_rejects_bad_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("RADIUS_MANAGED_FILE", "relative/netadmin")
    with pytest.raises(ValueError, match="RADIUS_MANAGED_FILE"):
        create_radius_agent()


def test_included_dhcp_pool_updates_its_own_file(monkeypatch, tmp_path):
    main = tmp_path / "dhcpd.conf"
    pools = tmp_path / "pools.conf"
    main.write_text('include "pools.conf";\n')
    pools.write_text(
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n  range 192.0.2.10 192.0.2.20;\n}\n"
    )
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_SERVER", "isc")
    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", lambda *args, **kwargs: None)
    client = create_dhcp_agent().test_client()
    inventory = client.get("/configuration", headers=AUTH).get_json()
    assert inventory[0]["source"] == str(pools)
    response = client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [["192.0.2.30", "192.0.2.40"]],
            "options": {},
        },
    )
    assert response.status_code == 200
    assert main.read_text() == 'include "pools.conf";\n'
    assert "range 192.0.2.30 192.0.2.40;" in pools.read_text()


def test_dhcp_agent_refuses_writes_to_external_include(monkeypatch, tmp_path):
    service = tmp_path / "service"
    service.mkdir()
    main = service / "dhcpd.conf"
    external = tmp_path / "external.conf"
    original = "subnet 192.0.2.0 netmask 255.255.255.0 {\n}\n"
    external.write_text(original)
    main.write_text(f'include "{external}";\n')
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(service / "reservations.conf"))
    monkeypatch.setenv("DHCP_SERVER", "isc")
    client = create_dhcp_agent().test_client()
    response = client.post(
        "/configuration",
        headers=AUTH,
        json={"network": "192.0.2.0", "ranges": [], "options": {}},
    )
    assert response.status_code == 400
    assert "configured service directories" in response.get_json()["error"]
    assert external.read_text() == original
