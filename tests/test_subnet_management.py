"""Independent subnet creation/removal for ISC and Kea, including rollback."""

import json
import subprocess

import pytest

from netadmin.agents.dhcp import create_dhcp_agent
from netadmin.services.subnet_files import create_subnet, remove_subnet

AUTH = {"Authorization": "Bearer synthetic"}


@pytest.mark.parametrize("backend", ["isc", "kea"])
def test_create_remove_subnet_preserves_configuration_and_leases(tmp_path, monkeypatch, backend):
    main = tmp_path / "main.conf"
    original = (
        "authoritative;\n" if backend == "isc" else '{"Dhcp4":{"valid-lifetime":3600,"subnet4":[]}}'
    )
    main.write_text(original)
    leases = tmp_path / "leases"
    leases.write_text("preserve leases")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("DHCP_SERVER", backend)
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_LEASES_FILE", str(leases))
    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", lambda *a, **k: None)
    client = create_dhcp_agent().test_client()
    assert client.post("/subnets", json={"cidr": "192.0.2.0/24"}).status_code == 401
    assert client.post("/subnets", headers=AUTH, json={"cidr": "192.0.2.0/24"}).status_code == 201
    assert client.post("/subnets", headers=AUTH, json={"cidr": "192.0.2.0/25"}).status_code == 409
    inventory = client.get("/configuration", headers=AUTH).json
    assert inventory[0]["network"] == "192.0.2.0"
    assert (
        client.post("/subnets/delete", headers=AUTH, json={"network": "192.0.2.0"}).status_code
        == 200
    )
    assert client.get("/configuration", headers=AUTH).json == []
    assert leases.read_text() == "preserve leases"
    assert main.with_name("main.conf.before-netadmin-subnets").read_text() == original
    if backend == "kea":
        assert json.loads(main.read_text())["Dhcp4"]["valid-lifetime"] == 3600
    else:
        assert "authoritative;" in main.read_text()


@pytest.mark.parametrize("kea", [False, True])
def test_failed_daemon_validation_rolls_back_creation(tmp_path, monkeypatch, kea):
    main = tmp_path / "main.conf"
    original = '{"Dhcp4":{"subnet4":[]}}' if kea else "authoritative;\n"
    main.write_text(original)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("DHCP_SERVER", "kea" if kea else "isc")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))

    def reject(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", reject)
    client = create_dhcp_agent().test_client()
    assert client.post("/subnets", headers=AUTH, json={"cidr": "192.0.2.0/24"}).status_code == 500
    assert main.read_text() == original


def test_kea_creation_ignores_commented_array():
    text = '# "subnet4": []\n{"Dhcp4":{"subnet4":[]}}'
    result = create_subnet(text, "192.0.2.0/24", 1, True)
    assert result.startswith('# "subnet4": []')
    assert len(json.loads(result.split("\n", 1)[1])["Dhcp4"]["subnet4"]) == 1


@pytest.mark.parametrize("index", [0, 1, 2])
def test_kea_remove_first_middle_and_last_subnet(index):
    items = [{"id": i + 1, "subnet": f"192.0.{i}.0/24", "pools": []} for i in range(3)]
    text = json.dumps({"Dhcp4": {"subnet4": items}})
    result = json.loads(remove_subnet(text, f"192.0.{index}.0", True))
    assert result["Dhcp4"]["subnet4"] == [item for i, item in enumerate(items) if i != index]


def test_kea_empty_array_with_comments_and_removal_separator():
    text = '{"Dhcp4":{"subnet4":[/* retained */]}}'
    created = create_subnet(text, "192.0.2.0/24", 1, True)
    assert "/* retained */" in created
    assert ",/* retained */]" not in created
    text = (
        '{"Dhcp4":{"subnet4":[{"subnet":"192.0.2.0/24"} /* note */, {"subnet":"198.51.100.0/24"}]}}'
    )
    assert "192.0.2.0" not in remove_subnet(text, "192.0.2.0", True)
