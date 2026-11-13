"""Reservation conflicts respect subnet scope and explain corrective actions."""

import pytest

from netadmin.agents.dhcp import create_dhcp_agent, parse_reservations
from tests.test_agent_endpoints import AUTH


@pytest.fixture
def reservation_agent(tmp_path, monkeypatch):
    main = tmp_path / "dhcpd.conf"
    included = tmp_path / "vlan.conf"
    managed = tmp_path / "managed.conf"
    main.write_text(
        "subnet 192.0.2.0 netmask 255.255.255.0 {}\n"
        "host device-one { hardware ethernet aa:bb:cc:dd:ee:01; fixed-address 192.0.2.5; }\n"
        f'include "{included}";\ninclude "{managed}";\n'
    )
    included.write_text("subnet 198.51.100.0 netmask 255.255.255.0 {}\n")
    managed.touch()
    monkeypatch.setenv("DHCP_SERVER", "isc")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(managed))
    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", lambda *_args, **_kwargs: None)
    return create_dhcp_agent().test_client(), main, managed


def test_isc_same_mac_can_have_reservations_in_different_included_subnets(reservation_agent):
    client, main, managed = reservation_agent
    before = main.read_bytes()
    payload = {"name": "device-two", "mac": "aa:bb:cc:dd:ee:01", "address": "198.51.100.5"}
    response = client.post("/reservations", headers=AUTH, json=payload)
    assert response.status_code == 200
    assert parse_reservations(managed.read_text()) == [payload]
    assert main.read_bytes() == before
    assert len(client.get("/reservations", headers=AUTH).json) == 2
    # Updating one VLAN's uniquely named reservation must retain the other.
    response = client.post(
        "/reservations", headers=AUTH, json={**payload, "address": "198.51.100.6"}
    )
    assert response.status_code == 200
    assert main.read_bytes() == before


@pytest.mark.parametrize("address", ["192.0.2.6", "203.0.113.6"])
def test_isc_same_or_unknown_subnet_mac_conflict_names_existing_reservation(
    reservation_agent, address
):
    client, main, managed = reservation_agent
    before = main.read_bytes()
    response = client.post(
        "/reservations",
        headers=AUTH,
        json={"name": "device-two", "mac": "aa:bb:cc:dd:ee:01", "address": address},
    )
    assert response.status_code == 409
    assert "device-one" in response.json["error"]
    assert "192.0.2.5" in response.json["error"]
    assert "distinct reservation name" in response.json["error"]
    assert main.read_bytes() == before
    assert managed.read_text() == ""


def test_address_conflict_identifies_existing_host_and_mac_without_writing(reservation_agent):
    client, main, managed = reservation_agent
    before = main.read_bytes()
    response = client.post(
        "/reservations",
        headers=AUTH,
        json={"name": "replacement", "mac": "aa:bb:cc:dd:ee:02", "address": "192.0.2.5"},
    )
    assert response.status_code == 409
    message = response.json["error"]
    for expected in ("IP address 192.0.2.5", "device-one", "aa:bb:cc:dd:ee:01", "Update or delete"):
        assert expected in message
    assert main.read_bytes() == before
    assert managed.read_text() == ""


def test_kea_global_mac_uniqueness_is_not_relaxed(tmp_path, monkeypatch):
    main = tmp_path / "kea4.conf"
    managed = tmp_path / "managed.json"
    main.write_text(
        '{"Dhcp4": {"reservations-global": true, "subnet4": ['
        '{"id": 1, "subnet": "192.0.2.0/24"},'
        '{"id": 2, "subnet": "198.51.100.0/24"}],'
        f'<?include "{managed}"?>' + "}}"
    )
    managed.write_text(
        '"reservations": [{"hostname": "device-one", "hw-address": "aa:bb:cc:dd:ee:01",'
        '"ip-address": "192.0.2.5"}]\n'
    )
    before = managed.read_bytes()
    monkeypatch.setenv("DHCP_SERVER", "kea")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(managed))
    response = (
        create_dhcp_agent()
        .test_client()
        .post(
            "/reservations",
            headers=AUTH,
            json={"name": "device-two", "mac": "aa:bb:cc:dd:ee:01", "address": "198.51.100.5"},
        )
    )
    assert response.status_code == 409
    assert "Kea global reservations require unique MAC addresses" in response.json["error"]
    assert managed.read_bytes() == before
