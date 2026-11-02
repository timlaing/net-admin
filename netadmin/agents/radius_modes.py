"""Agent-owned EAP mode transactions, validated and activated with rollback."""

from __future__ import annotations

import fcntl
import os
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from flask import Flask, current_app, jsonify

from netadmin.agents.common import configured_path, json_object, validated_transaction
from netadmin.agents.radius_certificates import _protocol_ready, _restart
from netadmin.services.radius_modes import configure, inventory, revision


def _paths() -> tuple[Path, Path]:
    return (
        cast(Path, current_app.config["RADIUS_EAP"]).resolve(),
        cast(Path, current_app.config["RADIUS_INNER_TUNNEL"]).resolve(),
    )


def _status() -> dict[str, Any]:
    eap, inner = _paths()
    try:
        result = inventory(eap.read_text(), inner.read_text())
        # Check edit support without touching the native files.
        configure(eap.read_text(), inner.read_text(), ["mschapv2"], "mschapv2")
    except (OSError, ValueError):
        return {
            "available": False,
            "can_manage": False,
            "uses_certificates": None,
            "reason": "Authentication settings are unavailable or require native editing.",
        }
    result["can_manage"] = (
        current_app.config["RADIUS_AUTH_MANAGEMENT"]
        and _protocol_ready()
        and all(os.access(path.parent, os.W_OK) for path in (eap, inner))
    )
    result["reason"] = (
        ""
        if result["can_manage"]
        else (
            "Enable authentication management on the agent, mount the EAP and inner-tunnel "
            "configuration directories writable, and configure RADIUS restart support."
        )
    )
    return result


def _get() -> Any:
    return jsonify(_status())


def _certificates_ready() -> None:
    root = Path(current_app.config["RADIUS_CERT_DIR"])
    now = datetime.now(UTC)
    for name in ("server.pem", "ca.pem"):
        certificate = x509.load_pem_x509_certificate((root / name).read_bytes())
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("Renew expired certificates before enabling PEAP or EAP-TLS")


def _apply(eap: Path, inner: Path, changes: tuple[str, str]) -> None:
    metadata = {path: path.stat() for path in (eap, inner)}
    restart_attempted = False

    def activate() -> None:
        nonlocal restart_attempted
        for path, original in metadata.items():
            path.chmod(original.st_mode & 0o777)
            os.chown(path, original.st_uid, original.st_gid)
        subprocess.run(["/usr/sbin/radiusd", "-XC"], check=True, capture_output=True, timeout=20)
        restart_attempted = True
        _restart()

    try:
        validated_transaction(
            dict(zip((eap, inner), changes, strict=True)),
            activate,
            [],
            allowed_roots=(eap.parent, inner.parent),
        )
    except Exception:
        if restart_attempted:
            _restart()
        raise


def _post() -> Any:
    body = json_object()
    modes = body.get("enabled")
    preferred = body.get("preferred")
    if (
        not isinstance(modes, list)
        or not all(isinstance(mode, str) for mode in modes)
        or not isinstance(preferred, str)
    ):
        return jsonify({"error": "Select supported authentication modes"}), 400
    if not current_app.config["RADIUS_AUTH_MANAGEMENT"] or not _protocol_ready():
        return jsonify({"error": "Authentication management is not enabled"}), 409
    try:
        lock_path = Path(current_app.config["RADIUS_CERT_DIR"]) / ".netadmin-cert-lock"
        if lock_path.is_symlink():
            raise ValueError("Unsafe lock file")
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            eap, inner = _paths()
            original = (eap.read_text(), inner.read_text())
            if body.get("revision") != revision(*original):
                return jsonify({"error": "Settings changed; reload this page before saving"}), 409
            changes = configure(*original, modes, preferred)
            if {"peap", "tls"}.intersection(modes):
                _certificates_ready()
            _apply(eap, inner, changes)
        return jsonify({"status": "applied"})
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return jsonify(
            {
                "error": "Authentication change failed; previous configuration restored. "
                "Check the RADIUS service status."
            }
        ), 502


def register_modes(app: Flask) -> None:
    """Expose safe inventory and restricted edits using the existing agent guards."""
    app.config.update(
        RADIUS_AUTH_MANAGEMENT=os.getenv("RADIUS_AUTH_MANAGEMENT", "false") == "true",
        RADIUS_EAP=configured_path("RADIUS_EAP_FILE", "/etc/raddb/mods-enabled/eap"),
        RADIUS_INNER_TUNNEL=configured_path(
            "RADIUS_INNER_TUNNEL_FILE", "/etc/raddb/sites-enabled/inner-tunnel"
        ),
    )
    app.add_url_rule("/authentication", view_func=_get, methods=["GET"])
    app.add_url_rule("/authentication", view_func=_post, methods=["POST"])
