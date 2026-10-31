"""Authentication and authorization helpers."""

from __future__ import annotations

import hmac
import posixpath
import subprocess  # nosec B404 - fixed executable and argv, no shell
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any, cast
from urllib.parse import unquote, urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import abort, current_app, g, has_request_context, redirect, request, url_for

from netadmin.config import Settings
from netadmin.store import SessionRecord, Store


@dataclass(frozen=True, slots=True)
class Identity:
    """Authenticated request identity."""

    username: str
    role: str


def verify_root(password_hash: str, password: str) -> bool:
    """Verify the emergency root password against an Argon2id hash."""
    try:
        return PasswordHasher().verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def authenticate_radius(username: str, password: str, settings: Settings) -> str | None:
    """Authenticate with radclient and map its reply attribute to a role."""
    if not settings.radius_enabled or not settings.radius_secret:
        return None
    packet = f"User-Name = {username!r}\nUser-Password = {password!r}\n"
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/radclient", "-x", settings.radius_host, "auth", settings.radius_secret],
        input=packet,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or "Access-Accept" not in result.stdout:
        return None
    for line in result.stdout.splitlines():
        if settings.radius_role_attribute not in line:
            continue
        _, _, raw_value = line.partition("=")
        value = raw_value.strip().strip('"')
        if hmac.compare_digest(value, settings.radius_admin_value):
            return "admin"
        if hmac.compare_digest(value, settings.radius_standard_value):
            return "standard"
    return "standard"


def load_identity() -> None:
    """Load the server-side session for the current request."""
    g.identity = None
    session_id = request.cookies.get("netadmin_session", "")
    if not session_id:
        return
    store = cast(Store, current_app.extensions["netadmin_store"])
    record: SessionRecord | None = store.get_session(session_id)
    if record is not None:
        g.identity = Identity(record.username, record.role)


def login_required[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Require an authenticated identity."""

    @wraps(view)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if g.get("identity") is None:
            return cast(
                R,
                redirect(url_for("web.login", next=f"{request.script_root}{request.full_path}")),
            )
        return view(*args, **kwargs)

    return wrapped


def admin_required[**P, R](view: Callable[P, R]) -> Callable[P, R]:
    """Require the administrator role."""

    @wraps(view)
    @login_required
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        identity = cast(Identity, g.identity)
        if identity.role != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def safe_next_url(value: str | None) -> str:
    """Allow only local absolute-path redirects."""
    # Backslashes are rejected as well: URL parsers treat "\\" as "/", so a
    # target like "/\\evil.example" would resolve to another origin even
    # though it starts with a single slash.
    prefix = request.script_root if has_request_context() else ""
    fallback = f"{prefix}/"
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return fallback
    if prefix:
        path = unquote(urlsplit(value).path)
        if "\\" in path or not posixpath.normpath(path).startswith(f"{prefix}/"):
            return fallback
    return value


def current_identity() -> Identity:
    """Return the identity after an authorization decorator has run."""
    return cast(Identity, g.identity)


def extension(name: str) -> Any:
    """Typed escape hatch for Flask extensions."""
    return current_app.extensions[name]
