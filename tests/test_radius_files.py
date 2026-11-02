"""Tests for safe FreeRADIUS configuration transforms."""

from netadmin.services.radius_files import (
    migrate_authorize,
    migrate_to_managed,
    parse_authorize,
    parse_clients,
    render_clients,
)
from netadmin.services.radius_users import ManagedUser, PasswordHashes


def test_migrate_preserves_entries_and_assigns_roles() -> None:
    source = """alice Cleartext-Password := "plain"
    Framed-Pool = "pool-parent"

bob Cleartext-Password := "another"
    Framed-Pool = "pool-child"
"""
    migrated, names = migrate_authorize(
        source,
        lambda value: PasswordHashes(f"hash-{value}", "a" * 32),
        {"pool-parent"},
        "netadmin-admin",
        "netadmin-standard",
    )
    assert names == ["alice", "bob"]
    assert "Cleartext-Password" not in migrated
    assert 'alice Crypt-Password := "hash-plain", NT-Password := 0x' in migrated
    assert 'Filter-Id := "netadmin-standard"' in migrated


def test_parse_authorize_never_returns_password() -> None:
    users = parse_authorize(
        'alice Crypt-Password := "$6$private", Filter-Id := "netadmin-admin"\n', "legacy"
    )
    assert users[0].username == "alice"
    assert users[0].role == "netadmin-admin"
    assert not hasattr(users[0], "password")


def test_client_round_trip_omits_secret() -> None:
    rendered = render_clients({"router": ("192.0.2.1", "gateway", "very-secret")})
    clients = parse_clients(rendered)
    assert clients[0].name == "router"
    assert clients[0].address == "192.0.2.1"
    assert not hasattr(clients[0], "secret")


def test_migration_moves_legacy_users_to_managed_entries() -> None:
    remaining, entries = migrate_to_managed(
        'alice Cleartext-Password := "plain"\n\tFramed-Pool = "pool-parent"\n',
        lambda value: PasswordHashes(f"hash-{value}", "a" * 32),
        {"pool-parent"},
        "netadmin-admin",
        "netadmin-standard",
    )
    assert "alice" not in remaining
    assert entries == {
        "alice": ManagedUser(
            PasswordHashes("hash-plain", "a" * 32),
            "netadmin-admin",
            replies='\n\tFramed-Pool = "pool-parent"\n',
        )
    }


def test_client_edit_rejects_nested_and_duplicate_definitions():
    import pytest

    from netadmin.services.radius_files import edit_client

    nested = "client router {\n ipaddr = 192.0.2.1\n tls {\n  mode = required\n }\n}\n"
    with pytest.raises(ValueError, match="Nested"):
        edit_client(nested, "router", None)
    duplicate = "client router {\n ipaddr = 192.0.2.1\n}\n" * 2
    with pytest.raises(ValueError, match="unambiguous"):
        edit_client(duplicate, "router", None)
    text = (
        'client router {\n ipaddr = 192.0.2.1\n shortname = "Home gateway"\n secret = hidden\n}\n'
    )
    assert parse_clients(text)[0].shortname == "Home gateway"
    changed = edit_client(text, "router", {"ipaddr": "192.0.2.10"})
    assert changed.startswith("client router {\n")
    assert 'shortname = "Home gateway"' in changed
    assert "secret = hidden" in changed
