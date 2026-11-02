"""Paired credentials, lossless updates, and safe legacy handling."""

from types import SimpleNamespace

import pytest

from netadmin.agents.radius import create_radius_agent, hash_passwords
from netadmin.services.radius_users import (
    ManagedUser,
    PasswordHashes,
    managed_entries,
    migrate_to_managed,
    parse_users,
    render_users,
)


def test_hash_passwords_encodes_nt_as_utf16_and_checks_both_results(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout="$6$salt$synthetic\n" if len(calls) == 1 else bytes(16))

    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", run)
    result = hash_passwords("pässword-🔑-long")
    assert result == PasswordHashes("$6$salt$synthetic", "0" * 32)
    assert calls[0][1]["input"] == "pässword-🔑-long"
    assert calls[1][1]["input"] == "pässword-🔑-long".encode("utf-16-le")
    assert calls[1][0][-2:] == ["-md4", "-binary"]
    assert "legacy" in calls[1][0]


@pytest.mark.parametrize(
    "password", ["short", "a" * 257, "ü" * 129, "long-password\n", "long-password\x00"]
)
def test_invalid_password_does_not_run_hashing(password, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Invalid passwords must be rejected before hashing")

    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", unexpected)
    with pytest.raises(ValueError):
        hash_passwords(password)


def test_disabled_pair_preserves_checks_replies_and_comments():
    original = ManagedUser(
        PasswordHashes("$6$synthetic", "a" * 32),
        "netadmin-admin",
        True,
        ("NAS-IP-Address == 192.0.2.1",),
        '\n\tFramed-Pool = "pool-parent",\n\tFramed-IP-Address = 192.0.2.8\n',
        "# retained comment",
    )
    rendered = render_users({"alice": original})
    assert all(line.startswith("#") for line in rendered.splitlines())
    assert managed_entries(rendered) == {"alice": original}


def test_migration_preserves_single_hashes_and_unsupported_stanzas():
    source = (
        'alice Crypt-Password := "$6$existing"\n\tFramed-Pool = "pool-parent"\n'
        "bob NT-Password := 0x" + "A" * 32 + "\n"
        "DEFAULT Auth-Type := Reject\n"
    )
    remaining, users = migrate_to_managed(
        source, lambda _: pytest.fail("Cannot rehash hashes"), {"pool-parent"}, "admin", "standard"
    )
    assert remaining == "DEFAULT Auth-Type := Reject\n"
    assert users["alice"].passwords == PasswordHashes("$6$existing")
    assert users["bob"].passwords == PasswordHashes(nt="a" * 32)
    metadata = parse_users(render_users(users))
    assert all(user["needs_password_reset"] for user in metadata)
    assert metadata[0]["mschapv2_ready"] is False
    assert metadata[1]["mschapv2_ready"] is True


@pytest.mark.parametrize(
    "source",
    [
        'alice Crypt-Password := "$6$x"\nalice NT-Password := 0x' + "a" * 32 + "\n",
        'alice Cleartext-Password := "secret",\n\tNAS-IP-Address == 192.0.2.1\n',
        "alice NT-Password := 0x1234\n",
    ],
)
def test_ambiguous_migration_aborts(source):
    with pytest.raises(ValueError):
        migrate_to_managed(source, lambda _: PasswordHashes("$6$x", "a" * 32), set(), "a", "s")


def test_agent_updates_both_hashes_preserves_replies_and_hides_values(tmp_path, monkeypatch):
    authorize = tmp_path / "authorize"
    managed = tmp_path / "managed"
    authorize.write_text("")
    existing = ManagedUser(
        PasswordHashes("$6$old", "a" * 32),
        "netadmin-standard",
        replies='\n\tFramed-Pool = "pool-parent"\n',
    )
    managed.write_text(render_users({"alice": existing}))
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_AUTHORIZE_FILE", str(authorize))
    monkeypatch.setenv("RADIUS_MANAGED_FILE", str(managed))
    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", lambda *a, **kw: None)
    monkeypatch.setattr(
        "netadmin.agents.radius.hash_passwords", lambda *a, **kw: PasswordHashes("$6$new", "b" * 32)
    )
    client = create_radius_agent().test_client()
    auth = {"Authorization": "Bearer synthetic"}
    response = client.post("/users", headers=auth, json={"username": "alice", "role": "admin"})
    assert response.status_code == 200
    assert managed_entries(managed.read_text())["alice"].passwords == existing.passwords
    response = client.post(
        "/users/password", headers=auth, json={"username": "alice", "password": "new-long-password"}
    )
    assert response.status_code == 200
    record = managed_entries(managed.read_text())["alice"]
    assert record.passwords == PasswordHashes("$6$new", "b" * 32)
    assert record.replies == existing.replies
    assert record.role == "netadmin-admin"
    response = client.get("/users", headers=auth)
    assert response.json[0]["needs_password_reset"] is False
    assert "$6$new" not in response.text
    assert "b" * 32 not in response.text


def test_agent_migration_failure_leaves_both_files_unchanged(tmp_path, monkeypatch):
    import subprocess

    authorize = tmp_path / "authorize"
    managed = tmp_path / "managed"
    source = 'alice Cleartext-Password := "old"\n\tFramed-Pool = "pool-parent"\n'
    authorize.write_text(source)
    managed.write_text("# Existing managed file\n")
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_AUTHORIZE_FILE", str(authorize))
    monkeypatch.setenv("RADIUS_MANAGED_FILE", str(managed))
    monkeypatch.setattr(
        "netadmin.agents.radius.hash_passwords", lambda *a, **kw: PasswordHashes("$6$new", "b" * 32)
    )

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["radiusd"])

    monkeypatch.setattr("netadmin.agents.radius.subprocess.run", fail)
    app = create_radius_agent()
    app.config["TESTING"] = True
    client = app.test_client()
    with pytest.raises(subprocess.CalledProcessError):
        client.post("/migration", headers={"Authorization": "Bearer synthetic"}, json={})
    assert authorize.read_text() == source
    assert managed.read_text() == "# Existing managed file\n"
