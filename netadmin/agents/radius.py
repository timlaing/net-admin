"""Restricted FreeRADIUS files-backend agent."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import subprocess  # nosec B404
import time
from collections.abc import Callable
from dataclasses import replace
from functools import wraps
from pathlib import Path
from typing import Any, cast

from flask import Flask, current_app, jsonify

from netadmin.agents.common import (
    configured_path,
    create_agent,
    json_object,
    validated_transaction,
)
from netadmin.agents.radius_certificates import register_certificates
from netadmin.agents.radius_modes import register_modes
from netadmin.agents.radius_state import file_lock, recover, transaction
from netadmin.agents.service_logs import register_logs
from netadmin.services.radius_files import (
    edit_client,
    parse_clients,
    render_clients,
)
from netadmin.services.radius_users import (
    ManagedUser,
    PasswordHashes,
    managed_entries,
    migrate_to_managed,
    parse_authorize,
    parse_users,
    render_users,
    user_blocks,
)

__all__ = ["create_radius_agent", "hash_password", "hash_passwords", "parse_users", "render_users"]


def _entries(text: str) -> dict[str, ManagedUser]:
    return managed_entries(text)


def validate_password(password: str, minimum_length: int = 12) -> None:
    """Reject invalid password length, UTF-8 byte size or unsupported characters."""
    if (
        len(password) < minimum_length
        or len(password.encode("utf-8")) > 256
        or any(c in password for c in "\x00\r\n")
    ):
        raise ValueError("Password length or characters are invalid")


def hash_passwords(
    password: str, *, minimum_length: int = 12, timeout: float = 10
) -> PasswordHashes:
    """Derive synchronized crypt and NT hashes from one validated plaintext value."""
    validate_password(password, minimum_length)
    crypt = subprocess.run(
        ["/usr/bin/openssl", "passwd", "-6", "-stdin"],
        input=password,
        text=True,
        capture_output=True,
        check=True,
        timeout=timeout,
    ).stdout.strip()
    nt = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-provider", "legacy", "-md4", "-binary"],
        input=password.encode("utf-16-le"),
        capture_output=True,
        check=True,
        timeout=timeout,
    ).stdout
    if not crypt.startswith("$6$") or len(nt) != 16:
        raise ValueError("Password hashing failed")
    return PasswordHashes(crypt, nt.hex())


def hash_password(password: str, *, minimum_length: int = 12) -> str:
    """Compatibility wrapper for callers expecting a crypt string."""
    return hash_passwords(password, minimum_length=minimum_length).crypt


def _managed_text(managed: Path) -> str:
    """Contents of a managed file, empty when it does not exist yet."""
    return managed.read_text(encoding="utf-8") if managed.exists() else ""


def _validate_radius() -> None:
    subprocess.run(
        ["/usr/sbin/radiusd", "-XC"],
        check=True,
        capture_output=True,
        timeout=20,
    )


def _path(key: str) -> Path:
    """Read a configured agent path from the application config."""
    return cast(Path, current_app.config[key])


def _pools() -> set[str]:
    """Read the configured admin framed-pool names from the application config."""
    return cast(set[str], current_app.config["RADIUS_ADMIN_POOLS"])


def _reload() -> list[str]:
    """Read the configured reload command from the application config."""
    return cast(list[str], current_app.config["RADIUS_RELOAD"])


def _journal() -> Path:
    return _path("RADIUS_MANAGED").parent / ".netadmin-users-transaction.json"


def _activate_users() -> None:
    _validate_radius()
    if _reload():
        subprocess.run(_reload(), check=True, timeout=30)  # noqa: S603


def _recover_users() -> None:
    recover(
        _journal(),
        {_path("RADIUS_AUTHORIZE").resolve(), _path("RADIUS_MANAGED").resolve()},
        _activate_users,
    )


def _serialized_users(view: Callable[[], Any]) -> Callable[[], Any]:
    @wraps(view)
    def locked() -> Any:
        with file_lock(_path("RADIUS_MANAGED").parent / ".netadmin-users.lock"):
            _recover_users()
            return view()

    return locked


def _write_users(managed: Path, entries: dict[str, ManagedUser], original: str) -> None:
    transaction(
        {managed: render_users(entries)},
        _validate_radius,
        _reload(),
        journal=_journal(),
        rollback=_activate_users,
        expected={managed.resolve(): original.encode() if managed.exists() else None},
    )


def _health() -> Any:
    return jsonify({"status": "ok"})


@_serialized_users
def _users() -> Any:
    legacy = parse_authorize(_path("RADIUS_AUTHORIZE").read_text(encoding="utf-8"), "authorize")
    return jsonify(
        [
            {
                "username": user.username,
                "role": user.role,
                "disabled": user.disabled,
                "source": user.source,
                "password_kind": user.password_kind,
            }
            for user in legacy
        ]
        + parse_users(_managed_text(_path("RADIUS_MANAGED")))
    )


def _preview_hash(password: str) -> PasswordHashes:
    validate_password(password, 1)
    return PasswordHashes("preview", "0" * 32)


def _migration_plan(
    hasher: Callable[[str], PasswordHashes],
) -> tuple[str, dict[str, ManagedUser], dict[Path, bytes | None]]:
    authorize = _path("RADIUS_AUTHORIZE")
    managed = _path("RADIUS_MANAGED")
    source = authorize.read_text(encoding="utf-8")
    original = _managed_text(managed)
    existing = _entries(original)
    # Verify eligibility and overlap before doing any expensive hashing.
    _, preview = migrate_to_managed(
        source, _preview_hash, _pools(), "netadmin-admin", "netadmin-standard"
    )
    if existing.keys() & preview.keys():
        raise ValueError("Legacy and managed usernames overlap")
    remaining, entries = migrate_to_managed(
        source, hasher, _pools(), "netadmin-admin", "netadmin-standard"
    )
    expected = {
        authorize.resolve(): source.encode(),
        managed.resolve(): original.encode() if managed.exists() else None,
    }
    return remaining, entries, expected


@_serialized_users
def _migration_preview() -> Any:
    try:
        _, entries, _ = _migration_plan(_preview_hash)
    except ValueError:
        return jsonify(
            {
                "users": [],
                "count": 0,
                "blocked": True,
                "reason": "Migration requires native editing: check unsupported entries, "
                "duplicate usernames or invalid legacy passwords.",
            }
        )
    names = sorted(entries)
    return jsonify({"users": names, "count": len(names), "blocked": False})


@_serialized_users
def _migration_apply() -> Any:
    deadline = time.monotonic() + 10

    def bounded_hash(password: str) -> PasswordHashes:
        if time.monotonic() >= deadline:
            raise ValueError(
                "Migration hashing budget exceeded; split the legacy file into batches"
            )
        return hash_passwords(password, minimum_length=1, timeout=5)

    remaining, legacy_entries, expected = _migration_plan(bounded_hash)
    authorize = _path("RADIUS_AUTHORIZE")
    managed = _path("RADIUS_MANAGED")
    original = _managed_text(managed)
    entries = _entries(original)
    entries.update(legacy_entries)
    transaction(
        {authorize: remaining, managed: render_users(entries)},
        _validate_radius,
        _reload(),
        journal=_journal(),
        rollback=_activate_users,
        expected=expected,
    )
    names = sorted(legacy_entries)
    return jsonify({"users": names, "count": len(names)})


@_serialized_users
def _save_user() -> Any:
    body = json_object()
    username = str(body.get("username", ""))
    if username == "DEFAULT" or not re.fullmatch(r"[A-Za-z0-9_.@-]+", username):
        return jsonify({"error": "Invalid username"}), 400
    managed = _path("RADIUS_MANAGED")
    original = _managed_text(managed)
    entries = _entries(original)
    if any(name == username for name, _ in user_blocks(_managed_text(_path("RADIUS_AUTHORIZE")))):
        return jsonify({"error": "Migrate this legacy user before editing it"}), 409
    existing = entries.get(username)
    password = str(body.get("password", ""))
    if password:
        password_hash = hash_passwords(password)
    elif existing:
        password_hash = existing.passwords
    else:
        password_hash = PasswordHashes()
    if not password_hash.kind:
        return jsonify({"error": "Password required for a new user"}), 400
    role = str(body.get("role", "standard"))
    role_value = "netadmin-admin" if role == "admin" else "netadmin-standard"
    disabled = bool(body.get("disabled", False))
    entries[username] = (
        replace(existing, passwords=password_hash, role=role_value, disabled=disabled)
        if existing
        else ManagedUser(password_hash, role_value, disabled)
    )
    _write_users(managed, entries, original)
    return jsonify({"username": username, "role": role, "disabled": disabled})


@_serialized_users
def _delete_user() -> Any:
    username = str(json_object().get("username", ""))
    managed = _path("RADIUS_MANAGED")
    original = _managed_text(managed)
    entries = _entries(original)
    entries.pop(username, None)
    _write_users(managed, entries, original)
    return jsonify({"deleted": username})


@_serialized_users
def _change_password() -> Any:
    body = json_object()
    username = str(body.get("username", ""))
    managed = _path("RADIUS_MANAGED")
    original = _managed_text(managed)
    entries = _entries(original)
    if username not in entries:
        return jsonify({"error": "Unknown user"}), 404
    entries[username] = replace(
        entries[username], passwords=hash_passwords(str(body.get("password", "")))
    )
    _write_users(managed, entries, original)
    return jsonify({"changed": username, "nonce": secrets.token_hex(4)})


def _clients() -> Any:
    return jsonify(
        [
            {
                "name": item.name,
                "address": item.address,
                "shortname": item.shortname,
                "source": source,
            }
            for source, path in [
                ("clients.conf", _path("RADIUS_CLIENTS")),
                ("netadmin", _path("RADIUS_MANAGED_CLIENTS")),
            ]
            for item in parse_clients(_managed_text(path))
        ]
    )


def _save_client() -> Any:
    body = json_object()
    name = str(body.get("name", ""))
    address = str(body.get("address", ""))
    shortname = str(body.get("shortname", name))
    secret_value = str(body.get("secret", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return jsonify({"error": "Valid client name required"}), 400
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError:
        return jsonify({"error": "Valid IP address or CIDR required"}), 400
    if any(char in shortname + secret_value for char in '\r\n\x00"\\'):
        return jsonify({"error": "Client values contain unsupported characters"}), 400
    existing = _client_target(name)
    if existing:
        values = {"ipaddr": address, "shortname": shortname}
        if secret_value:
            values["secret"] = secret_value
        _install_client(existing, edit_client(_managed_text(existing), name, values))
        return jsonify({"name": name, "address": address, "shortname": shortname})
    if len(secret_value) < 16:
        return jsonify({"error": "New clients require a secret of at least 16 characters"}), 400
    managed_clients = _path("RADIUS_MANAGED_CLIENTS")
    content = (
        _managed_text(managed_clients)
        + "\n"
        + render_clients({name: (address, shortname, secret_value)})
    )
    _install_client(managed_clients, content)
    return jsonify({"name": name, "address": address, "shortname": shortname})


def _delete_client() -> Any:
    name = str(json_object().get("name", ""))
    target = _client_target(name)
    if target is None:
        return jsonify({"error": "Client not found"}), 404
    _install_client(target, edit_client(_managed_text(target), name, None))
    return jsonify({"deleted": name})


def _client_target(name: str) -> Path | None:
    matches = [
        path
        for path in sorted({_path("RADIUS_CLIENTS"), _path("RADIUS_MANAGED_CLIENTS")})
        for item in parse_clients(_managed_text(path))
        if item.name == name
    ]
    if len(matches) > 1:
        raise ValueError("Duplicate client names require native configuration editing")
    return matches[0] if matches else None


def _install_client(target: Path, content: str) -> None:
    validated_transaction(
        {target: content},
        _validate_radius,
        _reload(),
        allowed_roots=(_path("RADIUS_CLIENTS").parent, _path("RADIUS_MANAGED_CLIENTS").parent),
    )


def create_radius_agent() -> Flask:
    """Create the FreeRADIUS management agent."""
    app = create_agent(__name__)
    register_logs(app, "radius")

    @app.errorhandler(ValueError)
    def invalid_client(_error: ValueError) -> Any:
        return jsonify(
            {"error": "Invalid or ambiguous user/client configuration; no changes were applied"}
        ), 400

    app.config.update(
        RADIUS_MANAGED=configured_path(
            "RADIUS_MANAGED_FILE", "/etc/raddb/mods-config/files/netadmin"
        ),
        RADIUS_AUTHORIZE=configured_path(
            "RADIUS_AUTHORIZE_FILE", "/etc/raddb/mods-config/files/authorize"
        ),
        RADIUS_CLIENTS=configured_path("RADIUS_CLIENTS_FILE", "/etc/raddb/clients.conf"),
        RADIUS_MANAGED_CLIENTS=configured_path(
            "RADIUS_MANAGED_CLIENTS_FILE", "/etc/raddb/netadmin-clients.conf"
        ),
        RADIUS_ADMIN_POOLS=set(
            filter(None, os.getenv("RADIUS_ADMIN_POOLS", "pool-parent").split(","))
        ),
        RADIUS_RELOAD=os.getenv("RADIUS_RELOAD_COMMAND", "").split(),
    )
    app.add_url_rule("/health", view_func=_health, methods=["GET"])
    app.add_url_rule("/users", view_func=_users, methods=["GET"])
    app.add_url_rule("/migration", view_func=_migration_preview, methods=["GET"])
    app.add_url_rule("/migration", view_func=_migration_apply, methods=["POST"])
    app.add_url_rule("/users", view_func=_save_user, methods=["POST"])
    app.add_url_rule("/users/delete", view_func=_delete_user, methods=["POST"])
    app.add_url_rule("/users/password", view_func=_change_password, methods=["POST"])
    app.add_url_rule("/clients", view_func=_clients, methods=["GET"])
    app.add_url_rule("/clients", view_func=_save_client, methods=["POST"])
    app.add_url_rule("/clients/delete", view_func=_delete_client, methods=["POST"])
    register_certificates(app)
    register_modes(app)
    with app.app_context():
        if _journal().exists():
            with file_lock(_path("RADIUS_MANAGED").parent / ".netadmin-users.lock"):
                _recover_users()
    return app


def _client_entries(text: str) -> dict[str, tuple[str, str, str]]:
    """Parse managed clients internally, including secrets required for rewrites."""
    result: dict[str, tuple[str, str, str]] = {}
    for match in re.finditer(r"(?ms)^client\s+([A-Za-z0-9_.-]+)\s*\{(.*?)^\}", text):
        body = match.group(2)
        values = {}
        for key in ("ipaddr", "shortname", "secret"):
            item = re.search(rf"(?m)^\s*{key}\s*=\s*([^\s#]+)", body)
            values[key] = item.group(1) if item else ""
        if values["ipaddr"] and values["secret"]:
            result[match.group(1)] = (values["ipaddr"], values["shortname"], values["secret"])
    return result


def main() -> None:
    """Run the development agent server."""
    # The container listens on every interface; mTLS and the token gate access.
    create_radius_agent().run(host="0.0.0.0", port=8082)  # noqa
