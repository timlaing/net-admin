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


@pytest.mark.parametrize("failure_mode", ["metadata", "inventory"])
@pytest.mark.parametrize("recovery", ["request", "startup"])
def test_nonroot_deletion_resumes_without_metadata(
    runtime,  # noqa: F811 - imported shared fixture
    tmp_path,
    monkeypatch,
    failure_mode,
    recovery,
):
    from netadmin.ca_runtime import store as storage
    from netadmin.ca_runtime.app import create_runtime
    from tests.test_ca_runtime import TOKEN

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    child_id = store.create_subordinate(body(parent_id=root_id, days=365, path_length=0))["id"]
    directory = store.directory(child_id)
    (directory / "config.json").write_text("{}")
    with store.inventory.connection() as connection:
        connection.execute(
            "INSERT INTO certificates VALUES (?, ?, ?)", (child_id, "leaf", "public")
        )
        connection.execute("INSERT INTO imported VALUES (?)", (child_id,))
        connection.execute("INSERT INTO processed VALUES (?, ?)", (child_id, "leaf"))
    payload = body(authority_id=child_id, confirmation="DELETE CA")

    def fail_directory(path):
        (path / "metadata.json").unlink()
        raise OSError("metadata removed before interruption")

    def fail_inventory(_authority_id):
        raise OSError("inventory cleanup interrupted")

    with monkeypatch.context() as patch:
        if failure_mode == "metadata":
            patch.setattr(storage, "_remove_authority_directory", fail_directory)
        else:
            patch.setattr(store.inventory, "remove_authority", fail_inventory)
        response = client.post("/authorities/delete", json=payload, headers=headers)
        assert response.status_code == 409
    assert not (directory / "metadata.json").exists()
    assert store.deletion_pending(child_id)
    assert _inventory_counts(store, child_id) == [1, 1, 1]
    original_operation = "/operations/" + payload["request_id"]
    assert client.get(original_operation, headers=headers).json["state"] == "attempted"
    wrong_payload = {**payload, "authority_id": root_id}
    assert (
        client.post("/authorities/delete", json=wrong_payload, headers=headers).status_code == 400
    )
    parent_delete = client.post(
        "/authorities/delete",
        headers=headers,
        json=body(authority_id=root_id, confirmation="DELETE CA"),
    )
    assert parent_delete.status_code == 400
    assert b"Delete child authorities first" in parent_delete.data
    app.extensions["ca_issuers"].reconcile()
    assert child_id not in app.extensions["ca_issuers"].processes
    pending_parent = client.post(
        "/authorities/subordinate", headers=headers, json=body(parent_id=child_id, days=30)
    )
    assert pending_parent.status_code == 400
    assert b"pending deletion" in pending_parent.data
    pending_issue = client.post(f"/authorities/{child_id}/issue", headers=headers, json=body())
    assert pending_issue.status_code == 400
    assert b"pending deletion" in pending_issue.data
    if recovery == "startup":
        app = create_runtime(tmp_path, TOKEN)
        store = app.extensions["ca_store"]
        client = app.test_client()
        assert not store.deletion_pending(child_id)
        assert not directory.exists()
        assert _inventory_counts(store, child_id) == [0, 0, 0]
    response = client.post("/authorities/delete", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json == {"deleted": child_id}
    assert client.get(original_operation, headers=headers).json == {
        "state": "complete",
        "result": {"deleted": child_id},
    }
    assert not directory.exists()
    assert not store.deletion_pending(child_id)
    assert _inventory_counts(store, child_id) == [0, 0, 0]
    assert not store.has_children(root_id)
    assert store.manifest["root_id"] == root_id


@pytest.mark.parametrize("recovery", ["startup", "retry"])
@pytest.mark.parametrize("failure", ["root.key", "record", "final-record"])
def test_root_reset_replays_after_interruption(runtime, tmp_path, monkeypatch, recovery, failure):  # noqa: F811
    import json

    from netadmin.ca_runtime import store as storage
    from netadmin.ca_runtime.app import create_runtime
    from tests.test_ca_runtime import TOKEN

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    payload = body(authority_id=root_id, confirmation="DELETE CA")
    record = tmp_path / "operations" / (payload["request_id"] + ".json")
    write = storage.durable
    completed_writes = 0

    def interrupted(path, data):
        nonlocal completed_writes
        if path == record and json.loads(data).get("state") == "complete":
            completed_writes += 1
            if completed_writes == (2 if failure == "final-record" else 1):
                raise OSError("simulated interruption")
        if failure == "root.key" and path.name == failure:
            raise OSError("simulated interruption")
        write(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "durable", interrupted)
        assert client.post("/authorities/delete", json=payload, headers=headers).status_code == 409
    if recovery == "startup":
        app = create_runtime(tmp_path, TOKEN)
        store = app.extensions["ca_store"]
        client = app.test_client()
        assert json.loads(record.read_text())["state"] == "complete"
        assert not (tmp_path / "root-reset.json").exists()
    response = client.post("/authorities/delete", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json == {"deleted": root_id}
    identity = store.manifest.copy()
    assert identity["root_id"] != root_id
    assert AuthorityStore(tmp_path).manifest == identity
    assert client.post("/authorities/delete", json=payload, headers=headers).json == response.json
    assert store.manifest == identity
    changed = {**payload, "authority_id": identity["root_id"]}
    assert client.post("/authorities/delete", json=changed, headers=headers).status_code == 400


def test_startup_deletion_failure_keeps_management_available(
    runtime,  # noqa: F811
    tmp_path,
    monkeypatch,
    caplog,
):
    from netadmin.ca_runtime import store as storage
    from netadmin.ca_runtime.app import create_runtime
    from tests.test_ca_runtime import TOKEN

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    children = [
        store.create_subordinate(body(parent_id=root_id, days=365, path_length=0))["id"]
        for _ in range(2)
    ]
    remove = storage._remove_authority_directory
    with monkeypatch.context() as patch:
        patch.setattr(
            storage, "_remove_authority_directory", lambda _: (_ for _ in ()).throw(OSError())
        )
        for child_id in children:
            payload = body(authority_id=child_id, confirmation="DELETE CA")
            assert (
                client.post("/authorities/delete", json=payload, headers=headers).status_code == 409
            )

    def fail_one(directory):
        if directory.name == children[0]:
            raise OSError("private filesystem detail")
        remove(directory)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "_remove_authority_directory", fail_one)
        app = create_runtime(tmp_path, TOKEN)
    recovered = app.extensions["ca_store"]
    assert app.test_client().get("/authorities", headers=headers).status_code == 200
    assert recovered.deletion_pending(children[0])
    assert not recovered.deletion_pending(children[1])
    assert not recovered.directory(children[1]).exists()
    assert children[0] in caplog.text
    assert "private filesystem detail" not in caplog.text
    app.extensions["ca_issuers"].reconcile()
    assert children[0] not in app.extensions["ca_issuers"].processes
    assert not AuthorityStore(tmp_path).deletion_pending(children[0])


@pytest.mark.parametrize("recovery", ["startup", "parent-delete"])
def test_incomplete_subordinate_cleanup_preserves_valid_authorities(
    runtime,  # noqa: F811
    tmp_path,
    monkeypatch,
    recovery,
):
    from netadmin.ca_runtime import store as storage

    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    original = store.manifest.copy()
    write = storage.durable

    def interrupted(path, data):
        if path.name == "metadata.json":
            raise OSError("simulated creation interruption")
        write(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "durable", interrupted)
        with store.lock(), pytest.raises(OSError, match="simulated creation interruption"):
            store.create_subordinate(body(parent_id=root_id, days=365, path_length=0))
    incomplete = [path for path in (tmp_path / "authorities").iterdir() if path.name != root_id]
    assert len(incomplete) == 1
    assert (incomplete[0] / "ca.key").exists()
    if recovery == "startup":
        store = AuthorityStore(tmp_path)
        assert store.manifest == original
        assert store.directory(root_id).exists()
    else:
        payload = body(authority_id=root_id, confirmation="DELETE CA")
        assert client.post("/authorities/delete", json=payload, headers=headers).status_code == 200
    assert not incomplete[0].exists()


def test_incomplete_root_is_not_cleaned(tmp_path):
    store = AuthorityStore(tmp_path)
    root_directory = store.directory(store.manifest["root_id"])
    root_directory.mkdir()
    (root_directory / "partial").write_text("interrupted root initialization")
    assert AuthorityStore(tmp_path).manifest == store.manifest
    assert root_directory.exists()
