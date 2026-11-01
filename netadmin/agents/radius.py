"""Restricted FreeRADIUS files-backend agent."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import subprocess  # nosec B404
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from flask import Flask, current_app, jsonify

from netadmin.agents.common import (
    atomic_validated_write,
    configured_path,
    create_agent,
    json_object,
    validated_transaction,
)
from netadmin.services.radius_files import (
    edit_client,
    migrate_authorize,
    migrate_to_managed,
    parse_authorize,
    parse_clients,
    render_clients,
)

USER_PATTERN = re.compile(
    r"^(?P<disabled>#DISABLED )?(?P<username>[A-Za-z0-9_.@-]+)\s+"
    r"Crypt-Password\s*:=\s*\"(?P<password>[^\"]+)\""
    r"(?:,\s*Filter-Id\s*:=\s*\"(?P<role>[^\"]+)\")?\s*$"
)


def parse_users(text: str) -> list[dict[str, Any]]:
    """Parse NetAdmin-managed RADIUS users without returning password hashes."""
    users = []
    for line in text.splitlines():
        match = USER_PATTERN.match(line)
        if match:
            users.append(
                {
                    "username": match.group("username"),
                    "role": match.group("role") or "netadmin-standard",
                    "disabled": bool(match.group("disabled")),
                }
            )
    return users


def _entries(text: str) -> dict[str, tuple[str, str, bool]]:
    result = {}
    for line in text.splitlines():
        match = USER_PATTERN.match(line)
        if match:
            result[match.group("username")] = (
                match.group("password"),
                match.group("role") or "netadmin-standard",
                bool(match.group("disabled")),
            )
    return result


def render_users(entries: dict[str, tuple[str, str, bool]]) -> str:
    """Render a dedicated FreeRADIUS users include."""
    lines = ["# Managed by NetAdmin. Password hashes are never returned by the API."]
    for username, (password_hash, role, disabled) in sorted(entries.items()):
        prefix = "#DISABLED " if disabled else ""
        lines.append(
            f'{prefix}{username} Crypt-Password := "{password_hash}", Filter-Id := "{role}"'
        )
    return "\n".join(lines) + "\n"


def hash_password(password: str) -> str:
    """Generate SHA-512 crypt for broad FreeRADIUS libc compatibility."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    result = subprocess.run(
        ["/usr/bin/openssl", "passwd", "-6", "-stdin"],
        input=password,
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return result.stdout.strip()


def _managed_text(managed: Path) -> str:
    """Contents of a managed file, empty when it does not exist yet."""
    return managed.read_text(encoding="utf-8") if managed.exists() else ""


def _stage_for(target: Path) -> Callable[[Path], None]:
    """Build a validator that stages a candidate into the live file for radiusd."""
    original = target.read_text(encoding="utf-8") if target.exists() else None

    def validate(candidate: Path) -> None:
        try:
            # False positive (S2083): target is a path the agent read from the
            # environment at startup via _configured_path(), which refuses
            # anything non-absolute or containing '..'; candidate is the agent's
            # own staged file. Neither is request-controlled.
            target.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")  # NOSONAR
            subprocess.run(
                ["/usr/sbin/radiusd", "-XC"],
                check=True,
                capture_output=True,
                timeout=20,
            )
        finally:
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_text(original, encoding="utf-8")

    return validate


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


def _health() -> Any:
    return jsonify({"status": "ok"})


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


def _migration_preview() -> Any:
    _, names = migrate_authorize(
        _path("RADIUS_AUTHORIZE").read_text(encoding="utf-8"),
        lambda _password: "preview",
        _pools(),
        "netadmin-admin",
        "netadmin-standard",
    )
    return jsonify({"users": names, "count": len(names)})


def _migration_apply() -> Any:
    authorize = _path("RADIUS_AUTHORIZE")
    managed = _path("RADIUS_MANAGED")
    remaining, legacy_entries = migrate_to_managed(
        authorize.read_text(encoding="utf-8"),
        hash_password,
        _pools(),
        "netadmin-admin",
        "netadmin-standard",
    )
    entries = _entries(_managed_text(managed))
    entries.update(legacy_entries)
    validated_transaction(
        {authorize: remaining, managed: render_users(entries)},
        _validate_radius,
        _reload(),
        allowed_roots=(authorize.parent, managed.parent),
    )
    names = sorted(legacy_entries)
    return jsonify({"users": names, "count": len(names)})


def _save_user() -> Any:
    body = json_object()
    username = str(body.get("username", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", username):
        return jsonify({"error": "Invalid username"}), 400
    managed = _path("RADIUS_MANAGED")
    entries = _entries(_managed_text(managed))
    existing = entries.get(username)
    password = str(body.get("password", ""))
    if password:
        password_hash = hash_password(password)
    elif existing:
        password_hash = existing[0]
    else:
        password_hash = ""
    if not password_hash:
        return jsonify({"error": "Password required for a new user"}), 400
    role = str(body.get("role", "standard"))
    role_value = "netadmin-admin" if role == "admin" else "netadmin-standard"
    disabled = bool(body.get("disabled", False))
    entries[username] = (password_hash, role_value, disabled)
    atomic_validated_write(managed, render_users(entries), _stage_for(managed), _reload())
    return jsonify({"username": username, "role": role, "disabled": disabled})


def _delete_user() -> Any:
    username = str(json_object().get("username", ""))
    managed = _path("RADIUS_MANAGED")
    entries = _entries(_managed_text(managed))
    entries.pop(username, None)
    atomic_validated_write(managed, render_users(entries), _stage_for(managed), _reload())
    return jsonify({"deleted": username})


def _change_password() -> Any:
    body = json_object()
    username = str(body.get("username", ""))
    managed = _path("RADIUS_MANAGED")
    entries = _entries(_managed_text(managed))
    if username not in entries:
        return jsonify({"error": "Unknown user"}), 404
    _, role, disabled = entries[username]
    entries[username] = (hash_password(str(body.get("password", ""))), role, disabled)
    atomic_validated_write(managed, render_users(entries), _stage_for(managed), _reload())
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

    @app.errorhandler(ValueError)
    def invalid_client(_error: ValueError) -> Any:
        return jsonify(
            {
                "error": "Invalid or ambiguous configuration; "
                "nested client definitions require native editing"
            }
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
