"""Shared service-agent security and file transaction helpers."""

from __future__ import annotations

import hmac
import os
import shutil
import subprocess  # nosec B404 - commands are fixed by the operator
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, request


class TransactionPathError(ValueError):
    """A discovered service filename is outside the agent's write boundary."""


class ConfigurationChanged(ValueError):
    """A native editor changed configuration while a candidate was being prepared."""


def create_agent(name: str) -> Flask:
    """Create an internal agent protected by a bearer token."""
    # Agents authenticate with a bearer token over mTLS: there are no cookie
    # sessions, so CSRF mitigation does not apply.
    app = Flask(name)  # NOSONAR
    expected = os.environ.get("NETADMIN_AGENT_TOKEN", "")
    if not expected:
        raise RuntimeError("NETADMIN_AGENT_TOKEN must be set")

    @app.before_request
    def authenticate() -> Any:
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, expected):
            abort(401)
        if os.getenv("NETADMIN_AGENT_READ_ONLY", "false") == "true" and request.method not in {
            "GET",
            "HEAD",
            "OPTIONS",
        }:
            return jsonify({"error": "Agent is configured read-only"}), 403
        return None

    @app.get("/capabilities")
    def capabilities() -> Any:
        return jsonify({"read_only": os.getenv("NETADMIN_AGENT_READ_ONLY", "false") == "true"})

    @app.errorhandler(TransactionPathError)
    def unsafe_path(_error: TransactionPathError) -> tuple[Any, int]:
        """Reject unsafe include paths without exposing filesystem details."""
        return jsonify({"error": "Write path is outside configured service directories"}), 400

    return app


def configured_path(name: str, default: str) -> Path:
    """Read an agent file path from the environment, refusing traversal tricks."""
    candidate = Path(os.getenv(name, default))
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{name} must be absolute and free of '..': {candidate}")
    return candidate


def atomic_validated_write(
    path: Path, content: str, validate: Callable[[Path], None], reload_command: list[str]
) -> None:
    """Validate a candidate, atomically install it, and roll back failed reloads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, candidate_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    candidate = Path(candidate_name)
    backup = path.with_suffix(f"{path.suffix}.{int(time.time())}.bak")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        candidate.chmod(0o640)
        validate(candidate)
        if path.exists():
            shutil.copy2(path, backup)
        os.replace(candidate, path)
        if reload_command:
            subprocess.run(reload_command, check=True, timeout=30)  # noqa: S603
    except Exception:
        if backup.exists():
            os.replace(backup, path)
        raise
    finally:
        candidate.unlink(missing_ok=True)


def validated_transaction(
    changes: dict[Path, str],
    validate: Callable[[], None],
    reload_command: list[str],
    *,
    allowed_roots: tuple[Path, ...],
    expected_originals: dict[Path, bytes | None] | None = None,
) -> None:
    """Install a group of files with validation and complete rollback on failure."""
    roots = tuple(root.resolve() for root in allowed_roots)
    # Includes are service configuration content, not permission to write anywhere.
    # Resolve links before every transaction and reject all paths before any writes.
    changes = {_transaction_path(path, roots): content for path, content in changes.items()}
    originals = {path: path.read_bytes() if path.exists() else None for path in changes}
    if expected_originals is not None and originals != expected_originals:
        raise ConfigurationChanged("Configuration changed before staging")
    candidates: dict[Path, Path] = {}
    installed = False
    try:
        for path, content in changes.items():
            descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            candidate = Path(name)
            candidate.chmod(0o640)
            candidates[path] = candidate
        current = {path: path.read_bytes() if path.exists() else None for path in changes}
        if current != originals:
            raise ConfigurationChanged("Configuration changed before installation")
        for path, candidate in candidates.items():
            os.replace(candidate, path)
            installed = True
        validate()
        if reload_command:
            subprocess.run(reload_command, check=True, timeout=30)  # noqa: S603
    except Exception:
        for path, original in originals.items() if installed else ():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)
        raise
    finally:
        for candidate in candidates.values():
            candidate.unlink(missing_ok=True)


def _transaction_path(path: Path, roots: tuple[Path, ...]) -> Path:
    """Constrain discovered filenames to explicitly configured service directories."""
    if not path.is_absolute() or ".." in path.parts:
        raise TransactionPathError("Transaction path must be absolute and free of '..'")
    resolved = path.resolve()
    if not any(resolved.is_relative_to(root) and resolved != root for root in roots):
        raise TransactionPathError("Transaction path is outside configured service directories")
    return resolved


def json_object() -> dict[str, Any]:
    """Return and validate a JSON object request body."""
    value = request.get_json(silent=False)
    if not isinstance(value, dict):
        abort(400, "JSON object required")
    return value
