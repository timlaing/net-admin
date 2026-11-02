"""Regression coverage for review findings, including interrupted native writes."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from werkzeug.datastructures import MultiDict

from netadmin.agents import common, radius_state
from netadmin.agents.radius import create_radius_agent, hash_password
from netadmin.forms import PasswordForm, RadiusUserForm
from netadmin.services.radius_modes import configure, inventory
from netadmin.services.radius_users import (
    ManagedUser,
    PasswordHashes,
    managed_entries,
    migrate_to_managed,
    render_users,
)
from tests.test_multi_service_ui import admin_client
from tests.test_radius_modes import AUTH, EAP, INNER


def user_agent(tmp_path, monkeypatch):
    authorize = tmp_path / "authorize"
    managed = tmp_path / "managed"
    authorize.touch()
    managed.touch()
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_AUTHORIZE_FILE", str(authorize))
    monkeypatch.setenv("RADIUS_MANAGED_FILE", str(managed))
    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", lambda *a, **kw: None)
    monkeypatch.setattr(
        "netadmin.agents.radius.hash_passwords",
        lambda *a, **kw: PasswordHashes("$6$synthetic", "a" * 32),
    )
    app = create_radius_agent()
    app.config["TESTING"] = True
    return app, authorize, managed


def test_concurrent_user_updates_preserve_both_users(tmp_path, monkeypatch):
    app, _, managed = user_agent(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    second_hash = threading.Event()

    def hash_pair(value, **kwargs):
        if value == "first-password":
            entered.set()
            assert release.wait(5)
        else:
            second_hash.set()
        return PasswordHashes("$6$synthetic", "a" * 32)

    monkeypatch.setattr("netadmin.agents.radius.hash_passwords", hash_pair)

    def save(name, password):
        return (
            app.test_client()
            .post("/users", headers=AUTH, json={"username": name, "password": password})
            .status_code
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(save, "alice", "first-password")
        assert entered.wait(5)
        second = pool.submit(save, "bob", "second-password")
        assert not second_hash.wait(0.05)
        release.set()
        assert first.result(timeout=5) == 200
        assert second.result(timeout=5) == 200
    assert set(managed_entries(managed.read_text())) == {"alice", "bob"}


def test_interrupted_migration_recovers_on_agent_startup(tmp_path, monkeypatch):
    _, authorize, managed = user_agent(tmp_path, monkeypatch)
    authorize.write_text('alice Cleartext-Password := "legacy"\n')
    original = authorize.read_text()
    real_replace = os.replace

    def stop_between_files(source, target):
        if Path(target) == managed:
            raise KeyboardInterrupt("Simulated process loss")
        real_replace(source, target)

    client = create_radius_agent().test_client()
    monkeypatch.setattr("netadmin.agents.common.os.replace", stop_between_files)
    with pytest.raises(KeyboardInterrupt):
        client.post("/migration", headers=AUTH, json={})
    journal = tmp_path / ".netadmin-users-transaction.json"
    assert journal.exists()
    assert journal.stat().st_mode & 0o777 == 0o600
    assert authorize.read_text() != original
    monkeypatch.setattr("netadmin.agents.common.os.replace", real_replace)
    create_radius_agent()
    assert authorize.read_text() == original
    assert managed.read_text() == ""
    assert not journal.exists()


def test_interrupted_mode_transaction_recovers_on_startup(tmp_path, monkeypatch):
    eap = tmp_path / "eap"
    inner = tmp_path / "inner"
    eap.write_text(EAP)
    inner.write_text(INNER)
    journal = tmp_path / ".netadmin-eap-transaction.json"
    changed_eap, changed_inner = configure(EAP, INNER, ["peap"], "peap")
    real_replace = os.replace

    def stop_between_files(source, target):
        if Path(target) == inner:
            raise KeyboardInterrupt("Simulated process loss")
        real_replace(source, target)

    monkeypatch.setattr("netadmin.agents.common.os.replace", stop_between_files)
    with pytest.raises(KeyboardInterrupt):
        radius_state.transaction(
            {eap: changed_eap, inner: changed_inner},
            lambda: None,
            [],
            journal=journal,
            rollback=lambda: None,
        )
    monkeypatch.setattr("netadmin.agents.common.os.replace", real_replace)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_EAP_FILE", str(eap))
    monkeypatch.setenv("RADIUS_INNER_TUNNEL_FILE", str(inner))
    monkeypatch.setenv("RADIUS_CERT_DIR", str(tmp_path))
    monkeypatch.setattr("netadmin.agents.radius_modes.subprocess.run", lambda *a, **kw: None)
    activated = []
    monkeypatch.setattr("netadmin.agents.radius_modes._restart", lambda: activated.append(True))
    create_radius_agent()
    assert eap.read_text() == EAP
    assert inner.read_text() == INNER
    assert activated == [True]
    assert not journal.exists()


def test_native_edit_during_staging_is_not_overwritten(tmp_path, monkeypatch):
    target = tmp_path / "native"
    target.write_text("original")
    real_sync = os.fsync

    def native_edit(descriptor):
        target.write_text("native edit")
        real_sync(descriptor)

    monkeypatch.setattr("netadmin.agents.common.os.fsync", native_edit)
    with pytest.raises(common.ConfigurationChanged):
        common.validated_transaction(
            {target: "candidate"}, lambda: None, [], allowed_roots=(tmp_path,)
        )
    assert target.read_text() == "native edit"


@pytest.mark.parametrize(
    "source",
    [
        'alice Cleartext-Password := "valid",\n\tNAS-IP-Address == 192.0.2.1\n',
        'alice Cleartext-Password := "' + "ü" * 129 + '"\n',
    ],
)
def test_migration_limitations_are_renderable_metadata(tmp_path, monkeypatch, source):
    app, authorize, _ = user_agent(tmp_path, monkeypatch)
    authorize.write_text(source)
    response = app.test_client().get("/migration", headers=AUTH)
    assert response.status_code == 200
    assert response.json["blocked"] is True
    assert response.json["count"] == 0
    assert app.test_client().get("/users", headers=AUTH).status_code == 200


def test_migration_preview_blocks_overlapping_users(tmp_path, monkeypatch):
    app, authorize, managed = user_agent(tmp_path, monkeypatch)
    authorize.write_text('alice Cleartext-Password := "legacy"\n')
    managed.write_text(render_users({"alice": ManagedUser(PasswordHashes("$6$old"), "standard")}))
    assert app.test_client().get("/migration", headers=AUTH).json["blocked"] is True


def test_filter_comparisons_and_legacy_string_callbacks_are_preserved():
    source = 'alice Crypt-Password := "$6$existing", Filter-Id == "request-role"\n'
    _, users = migrate_to_managed(
        source, lambda value: "$6$old-callback", set(), "admin", "standard"
    )
    assert users["alice"].checks == ('Filter-Id == "request-role"',)
    source = 'alice Cleartext-Password := "legacy"\n'
    _, users = migrate_to_managed(
        source, lambda value: "$6$old-callback", set(), "admin", "standard"
    )
    assert users["alice"].passwords.crypt == "$6$old-callback"
    assert users["alice"].passwords.nt == ""


def test_multiple_filter_assignments_are_rejected_before_rewrite():
    source = 'alice Crypt-Password := "$6$x", Filter-Id := "first", Filter-Id := "second"\n'
    with pytest.raises(ValueError):
        migrate_to_managed(source, lambda value: "$6$unused", set(), "admin", "standard")


def test_hash_password_preserves_crypt_string_contract(monkeypatch):
    monkeypatch.setattr(
        "netadmin.agents.radius.hash_passwords",
        lambda *a, **kw: PasswordHashes("$6$synthetic", "a" * 32),
    )
    assert hash_password("long-synthetic-password") == "$6$synthetic"


@pytest.mark.parametrize(
    "value,valid", [("ü" * 128, True), ("ü" * 129, False), ("a" * 12 + "\n", False)]
)
def test_password_forms_enforce_utf8_bytes(tmp_path, value, valid):
    app, _ = admin_client(tmp_path)
    with app.test_request_context():
        create = RadiusUserForm(MultiDict({"password": value}))
        change = PasswordForm(MultiDict({"new_password": value}))
        assert create.password.validate(create) is valid
        assert change.new_password.validate(change) is valid


def test_comments_without_spaces_are_not_active_methods():
    source = EAP.replace(" default_eap_type = md5", "#no-space {\n default_eap_type = md5")
    assert inventory(source, INNER)["enabled"] == ["mschapv2", "peap", "tls"]
    configured, inner = configure(source, INNER, ["mschapv2"], "mschapv2")
    assert inventory(configured, inner)["enabled"] == ["mschapv2"]


def test_mode_activation_failure_shows_recovery_warning(tmp_path):
    app, client = admin_client(tmp_path)

    def reject(path, payload, **kwargs):
        request = httpx.Request("POST", "https://synthetic/authentication")
        raise httpx.HTTPStatusError(
            "rejected", request=request, response=httpx.Response(502, request=request)
        )

    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: False,
        post=reject,
        get=lambda path: {"available": False, "reason": "Synthetic status"},
    )
    response = client.post("/radius/authentication", data={"confirm": "yes"}, follow_redirects=True)
    assert response.status_code == 200
    assert "rollback was attempted" in response.text


def test_legacy_user_conflict_shows_migration_requirement(tmp_path):
    app, client = admin_client(tmp_path)

    def reject(path, payload, **kwargs):
        request = httpx.Request("POST", "https://synthetic/users")
        raise httpx.HTTPStatusError(
            "legacy", request=request, response=httpx.Response(409, request=request)
        )

    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: False,
        post=reject,
        get=lambda path: (
            {"available": False}
            if path == "authentication"
            else ({"count": 0} if path == "migration" else [])
        ),
    )
    response = client.post(
        "/radius", data={"username": "alice", "role": "standard"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert "Migrate this legacy user" in response.text
