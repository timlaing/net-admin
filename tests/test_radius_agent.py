"""Tests for FreeRADIUS user rendering."""

from netadmin.agents.radius import _client_entries, parse_users, render_users


def test_user_output_never_contains_hash() -> None:
    rendered = render_users({"alice": ("$6$secret-hash", "netadmin-standard", False)})
    users = parse_users(rendered)
    assert users == [{"username": "alice", "role": "netadmin-standard", "disabled": False}]
    assert "password" not in users[0]


def test_disabled_user() -> None:
    rendered = render_users({"bob": ("$6$hash", "netadmin-admin", True)})
    assert parse_users(rendered)[0]["disabled"] is True


def test_internal_client_entries_preserve_secret_for_rewrite() -> None:
    entries = _client_entries(
        """client router {
  ipaddr = 192.0.2.1
  shortname = gateway
  secret = private-value
}
"""
    )
    assert entries == {"router": ("192.0.2.1", "gateway", "private-value")}


def test_existing_clients_edit_preserves_secret_and_unknown_attributes(tmp_path, monkeypatch):
    from netadmin.agents.radius import create_radius_agent

    main = tmp_path / "clients.conf"
    original = (
        "# keep comment\nclient router {\n ipaddr = 192.0.2.1\n"
        ' secret = "original secret"\n shortname = old\n nas_type = other\n}\n'
        "client other {\n ipaddr = 192.0.2.2\n secret = other-secret\n}\n"
    )
    main.write_text(original)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_CLIENTS_FILE", str(main))
    monkeypatch.setenv("RADIUS_MANAGED_CLIENTS_FILE", str(tmp_path / "managed.conf"))
    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", lambda *a, **k: None)
    client = create_radius_agent().test_client()
    auth = {"Authorization": "Bearer synthetic"}
    rows = client.get("/clients", headers=auth).json
    assert rows[0]["source"] == "clients.conf"
    assert all("secret" not in row for row in rows)
    response = client.post(
        "/clients",
        headers=auth,
        json={"name": "router", "address": "192.0.2.10", "shortname": "updated", "secret": ""},
    )
    assert response.status_code == 200
    assert 'secret = "original secret"' in main.read_text()
    assert "nas_type = other" in main.read_text()
    assert 'ipaddr = "192.0.2.10"' in main.read_text()
    assert client.get("/clients", headers=auth).json[0]["address"] == "192.0.2.10"
    assert client.post("/clients/delete", headers=auth, json={"name": "router"}).status_code == 200
    assert "client router" not in main.read_text()
    assert "client other" in main.read_text()
    assert client.post("/clients/delete", headers=auth, json={"name": "missing"}).status_code == 404


def test_client_edit_rolls_back_validation_failure_and_blocks_injection(tmp_path, monkeypatch):
    import subprocess

    from netadmin.agents.radius import create_radius_agent

    main = tmp_path / "clients.conf"
    original = "client router {\n ipaddr = 192.0.2.1\n secret = hidden\n}\n"
    main.write_text(original)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_CLIENTS_FILE", str(main))
    monkeypatch.setenv("RADIUS_MANAGED_CLIENTS_FILE", str(tmp_path / "managed.conf"))
    client = create_radius_agent().test_client()
    auth = {"Authorization": "Bearer synthetic"}

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["radiusd"])

    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", fail)
    client.application.config["TESTING"] = True
    import pytest

    with pytest.raises(subprocess.CalledProcessError):
        client.post("/clients/delete", headers=auth, json={"name": "router"})
    assert main.read_text() == original
    response = client.post(
        "/clients",
        headers=auth,
        json={"name": "router", "address": "192.0.2.10", "shortname": "evil\nsecret = injected"},
    )
    assert response.status_code == 400
    assert main.read_text() == original
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.get("/capabilities", headers=auth).json == {"read_only": True}
    assert client.post("/clients/delete", headers=auth, json={"name": "router"}).status_code == 403
    assert main.read_text() == original
