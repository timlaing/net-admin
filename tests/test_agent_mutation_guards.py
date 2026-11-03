"""Native service mutation guards preserve original configuration on rejection."""

from types import SimpleNamespace

import pytest
from flask import Flask

from netadmin.agents import dhcp, radius, radius_state
from netadmin.agents.dhcp import create_dhcp_agent
from tests.test_agent_endpoints import AUTH as DHCP_AUTH
from tests.test_radius_modes import AUTH
from tests.test_radius_review import user_agent


@pytest.fixture
def dhcp_state(tmp_path, monkeypatch):
    main = tmp_path / "dhcpd.conf"
    managed = tmp_path / "managed.conf"
    leases = tmp_path / "leases"
    managed.touch()
    leases.write_text("retained synthetic leases")
    main.write_text(
        "subnet 192.0.2.0 netmask 255.255.255.0 { range 192.0.2.10 192.0.2.20; }\n"
        "host legacy { hardware ethernet aa:bb:cc:dd:ee:01; fixed-address 192.0.2.5; }\n"
        f'include "{managed}";\n'
    )
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("DHCP_MAIN_CONFIG", str(main))
    monkeypatch.setenv("DHCP_MANAGED_FILE", str(managed))
    monkeypatch.setenv("DHCP_LEASES_FILE", str(leases))
    monkeypatch.setattr(dhcp.subprocess, "run", lambda *_args, **_kwargs: None)
    return SimpleNamespace(
        main=main, managed=managed, leases=leases, client=create_dhcp_agent().test_client()
    )


def test_dhcp_invalid_reservations_conflicts_and_external_move(dhcp_state):
    state = dhcp_state
    before = state.main.read_bytes()
    assert state.client.get("/health", headers=DHCP_AUTH).json == {"status": "ok"}
    for invalid in ({"name": "bad/name"}, {"mac": "not-a-mac"}, {"address": "not-an-ip"}):
        payload = {"name": "other", "mac": "aa:bb:cc:dd:ee:02", "address": "192.0.2.6", **invalid}
        assert (
            state.client.post("/reservations", headers=DHCP_AUTH, json=payload).status_code == 400
        )
    assert (
        state.client.post(
            "/reservations",
            headers=DHCP_AUTH,
            json={"name": "duplicate", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.6"},
        ).status_code
        == 409
    )
    assert state.main.read_bytes() == before
    assert state.managed.read_text() == ""
    response = state.client.post(
        "/reservations",
        headers=DHCP_AUTH,
        json={"name": "legacy", "mac": "aa:bb:cc:dd:ee:02", "address": "192.0.2.6"},
    )
    assert response.status_code == 200
    assert "host legacy" not in state.main.read_text()
    assert "host legacy" in state.managed.read_text()
    assert state.leases.read_text() == "retained synthetic leases"


def test_dhcp_invalid_subnet_edits_and_remove_backup(dhcp_state):
    state = dhcp_state
    before = state.main.read_bytes()
    for payload, status in (
        ({"network": "192.0.2.0", "ranges": {}, "options": {}}, 400),
        ({"network": "198.51.100.0", "ranges": [], "options": {}}, 404),
        ({"network": "192.0.2.0", "ranges": [["not-an-ip", "192.0.2.20"]], "options": {}}, 400),
        ({"network": "192.0.2.0", "ranges": [["192.0.2.10"]], "options": {}}, 400),
    ):
        assert (
            state.client.post("/configuration", headers=DHCP_AUTH, json=payload).status_code
            == status
        )
    assert (
        state.client.post("/subnets", headers=DHCP_AUTH, json={"cidr": "invalid"}).status_code
        == 400
    )
    assert (
        state.client.post(
            "/subnets/delete", headers=DHCP_AUTH, json={"network": "198.51.100.0"}
        ).status_code
        == 404
    )
    assert state.main.read_bytes() == before
    response = state.client.post(
        "/subnets/delete", headers=DHCP_AUTH, json={"network": "192.0.2.0"}
    )
    assert response.status_code == 200
    assert response.json["leases_preserved"]
    assert state.main.with_name(state.main.name + ".before-netadmin-subnets").read_bytes() == before
    assert state.leases.read_text() == "retained synthetic leases"


def test_ambiguous_dhcp_subnet_discovery_is_rejected(tmp_path):
    source = tmp_path / "dhcpd.conf"
    source.write_text(
        "subnet 192.0.2.0 netmask 255.255.255.0 {}\nsubnet 192.0.2.0 netmask 255.255.255.0 {}\n"
    )
    with pytest.raises(ValueError, match="Ambiguous subnet"):
        dhcp._all_subnets(source)


def test_radius_user_and_client_invalid_inputs_retain_native_files(tmp_path, monkeypatch):
    app, authorize, _managed = user_agent(tmp_path, monkeypatch)
    native = tmp_path / "clients.conf"
    native.write_text(
        "client ap { ipaddr = 192.0.2.10\n secret = synthetic-existing-secret\n shortname = ap\n}\n"
    )
    managed_clients = tmp_path / "managed-clients.conf"
    managed_clients.touch()
    app.config.update(RADIUS_CLIENTS=native, RADIUS_MANAGED_CLIENTS=managed_clients)
    client = app.test_client()
    original = native.read_bytes()
    authorize.write_text('legacy Cleartext-Password := "synthetic-password"\n')
    authorize_before = authorize.read_bytes()
    assert client.get("/health", headers=AUTH).json == {"status": "ok"}
    for payload in (
        {"username": "DEFAULT", "password": "synthetic-password"},
        {"username": "new", "password": ""},
    ):
        assert client.post("/users", headers=AUTH, json=payload).status_code == 400
    assert authorize.read_bytes() == authorize_before
    assert (
        client.post(
            "/users",
            headers=AUTH,
            json={"username": "legacy", "password": "new-synthetic-password"},
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/users/password",
            headers=AUTH,
            json={"username": "unknown", "password": "synthetic-password"},
        ).status_code
        == 404
    )
    for payload in (
        {"name": "bad/name", "address": "192.0.2.20", "secret": "synthetic-new-secret"},
        {"name": "new", "address": "192.0.2.20", "secret": "short"},
    ):
        assert client.post("/clients", headers=AUTH, json=payload).status_code == 400
    assert native.read_bytes() == original
    assert managed_clients.read_text() == ""
    assert (
        client.post(
            "/clients",
            headers=AUTH,
            json={
                "name": "ap",
                "address": "192.0.2.11",
                "shortname": "new-ap",
                "secret": "synthetic-replaced-secret",
            },
        ).status_code
        == 200
    )
    assert "synthetic-replaced-secret" in native.read_text()
    assert "192.0.2.11" in native.read_text()
    managed_clients.write_text(native.read_text())
    assert client.post("/clients/delete", headers=AUTH, json={"name": "ap"}).status_code == 400


def test_radius_rejects_failed_hash_derivation_and_preserves_secret_stdin(monkeypatch):
    commands = []

    def execute(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(stdout="invalid-crypt" if "passwd" in command else b"short")

    monkeypatch.setattr(radius.subprocess, "run", execute)
    with pytest.raises(ValueError, match="hashing failed"):
        radius.hash_passwords("synthetic-password")
    assert len(commands) == 2
    assert commands[0][1]["input"] == "synthetic-password"
    assert commands[1][1]["input"] == "synthetic-password".encode("utf-16-le")
    assert all("synthetic-password" not in command for command, _kwargs in commands)


def test_radius_user_activation_validates_before_operator_reload(monkeypatch):
    app = Flask("radius-activation")
    app.config["RADIUS_RELOAD"] = ["synthetic", "reload"]
    events = []
    monkeypatch.setattr(radius, "_validate_radius", lambda: events.append("validate"))

    def execute(command, **kwargs):
        assert command == ["synthetic", "reload"]
        assert kwargs == {"check": True, "timeout": 30}
        events.append("reload")

    monkeypatch.setattr(radius.subprocess, "run", execute)
    with app.app_context():
        radius._activate_users()
    assert events == ["validate", "reload"]


def test_new_radius_file_transaction_has_durable_commit_and_clears_journal(tmp_path):
    path = tmp_path / "users"
    journal = tmp_path / "journal"

    def validate():
        assert journal.exists()
        assert path.read_text() == "created"

    radius_state.transaction(
        {path: "created"},
        validate,
        [],
        journal=journal,
        rollback=lambda: pytest.fail("Successful update must not roll back"),
    )
    assert path.read_text() == "created"
    assert not journal.exists()
