"""Explicit authority removal, fresh root identities and service visibility."""

from dataclasses import replace

import pytest

from netadmin.ca_runtime.store import AuthorityStore
from tests.test_ca_runtime import body, runtime  # noqa: F401
from tests.test_multi_service_ui import admin_client


def test_root_delete_requires_confirmation_and_rotates_identity(runtime, tmp_path):  # noqa: F811
    app, client, headers = runtime
    store = app.extensions["ca_store"]
    original = store.manifest.copy()
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    payload = body(authority_id=root_id, confirmation="wrong")
    assert client.post("/authorities/delete", json=payload, headers=headers).status_code == 400
    assert store.directory(root_id).exists()
    payload = body(authority_id=root_id, confirmation="DELETE CA")
    assert client.post("/authorities/delete", json=payload).status_code == 403
    response = client.post("/authorities/delete", json=payload, headers=headers)
    assert response.status_code == 200
    assert client.post("/authorities/delete", json=payload, headers=headers).json == response.json
    assert store.status()["authorities"] == []
    assert store.manifest["root_id"] != original["root_id"]
    assert store.manifest["public_key_sha256"] != original["public_key_sha256"]
    assert AuthorityStore(tmp_path).manifest == store.manifest
    assert client.post("/authorities/root", json=body(), headers=headers).status_code == 200


def test_delete_children_before_parent(runtime):  # noqa: F811
    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    child_id = store.create_subordinate(body(parent_id=root_id, days=365, path_length=0))["id"]
    response = client.post(
        "/authorities/delete",
        headers=headers,
        json=body(authority_id=root_id, confirmation="DELETE CA"),
    )
    assert response.status_code == 400
    assert b"Delete child authorities first" in response.data
    for authority_id in (child_id, root_id):
        response = client.post(
            "/authorities/delete",
            headers=headers,
            json=body(authority_id=authority_id, confirmation="DELETE CA"),
        )
        assert response.status_code == 200
        assert not store.directory(authority_id).exists()


def test_dashboard_and_navigation_only_show_enabled_services(tmp_path):
    app, client = admin_client(tmp_path)
    settings = app.extensions["netadmin_settings"]
    app.extensions["netadmin_settings"] = replace(
        settings,
        dns_enabled=False,
        dhcp_enabled=False,
        radius_enabled=False,
        ca_agent_url="https://ca.example.test:8084",
        ca_enabled=True,
    )
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode()
    assert "<h2>CA</h2>" in html
    assert "<span>CA</span>" in html
    for service in ("DNS", "DHCP", "RADIUS"):
        assert f"<h2>{service}</h2>" not in html
        assert f"<span>{service}</span>" not in html
    assert "/connections/status/ca" in html


def _inventory_counts(store, authority_id):
    with store.inventory.connection() as connection:
        return [
            connection.execute(statement, (authority_id,)).fetchone()[0]
            for statement in (
                "SELECT count(*) FROM certificates WHERE authority=?",
                "SELECT count(*) FROM imported WHERE authority=?",
                "SELECT count(*) FROM processed WHERE authority=?",
            )
        ]


@pytest.mark.parametrize("failure_file", ["root-reset.json", "root.key"])
def test_root_reset_inventory_follows_durable_intent(runtime, tmp_path, monkeypatch, failure_file):  # noqa: F811
    from netadmin.ca_runtime import store as storage

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    original = store.manifest.copy()
    with store.inventory.connection() as connection:
        connection.execute("INSERT INTO certificates VALUES (?, ?, ?)", (root_id, "leaf", "public"))
        connection.execute("INSERT INTO imported VALUES (?)", (root_id,))
        connection.execute("INSERT INTO processed VALUES (?, ?)", (root_id, "leaf"))
    before = _inventory_counts(store, root_id)
    assert before == [1, 1, 1]
    write = storage.durable

    def interrupted(path, data):
        if path.name == failure_file:
            raise OSError("simulated interruption")
        write(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "durable", interrupted)
        payload = body(authority_id=root_id, confirmation="DELETE CA")
        with store.lock(), pytest.raises(OSError, match="simulated interruption"):
            store.delete_authority(payload)
    recovered = AuthorityStore(tmp_path)
    assert not (tmp_path / "root-reset.json").exists()
    if failure_file == "root-reset.json":
        assert recovered.manifest == original
        assert [authority["id"] for authority in recovered.status()["authorities"]] == [root_id]
        assert _inventory_counts(recovered, root_id) == before
    else:
        assert recovered.status()["authorities"] == []
        assert recovered.manifest["public_key_sha256"] != original["public_key_sha256"]
        assert _inventory_counts(recovered, root_id) == [0, 0, 0]


def test_failed_intermediate_directory_removal_preserves_inventory(runtime, monkeypatch):  # noqa: F811
    from netadmin.ca_runtime import store as storage

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    child_id = store.create_subordinate(body(parent_id=root_id, days=365, path_length=0))["id"]
    directory = store.directory(child_id)
    leaf = directory / "leaf.pem"
    leaf.write_bytes(store.chain(child_id))
    with store.inventory.connection() as connection:
        connection.execute(
            "INSERT INTO certificates VALUES (?, ?, ?)", (child_id, "leaf", "public")
        )
        connection.execute("INSERT INTO imported VALUES (?)", (child_id,))
        connection.execute("INSERT INTO processed VALUES (?, ?)", (child_id, "leaf"))
    before = _inventory_counts(store, child_id)

    def interrupted(path):
        (path / "leaf.pem").unlink()
        raise OSError("partial directory removal")

    payload = body(authority_id=child_id, confirmation="DELETE CA")
    with monkeypatch.context() as patch:
        patch.setattr(storage, "_remove_authority_directory", interrupted)
        with store.lock(), pytest.raises(OSError, match="partial directory removal"):
            store.delete_authority(payload)
    assert not leaf.exists()
    assert store.metadata(child_id)["parent_id"] == root_id
    assert _inventory_counts(store, child_id) == before == [1, 1, 1]
    with store.lock():
        assert store.delete_authority(payload) == {"deleted": child_id}
    assert not directory.exists()
    assert _inventory_counts(store, child_id) == [0, 0, 0]
