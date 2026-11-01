"""Restricted RADIUS certificate endpoints and transactional activation."""

from __future__ import annotations

import fcntl
import os
import secrets
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from flask import Flask, current_app, jsonify

from netadmin.agents.common import configured_path, json_object, validated_transaction
from netadmin.services.radius_certificates import (
    PEM,
    certificate_changes,
    certificate_info,
    key_matches,
    load_signing_key,
)


def _root() -> Path:
    return Path(current_app.config["RADIUS_CERT_DIR"])


def _password() -> bytes:
    return str(current_app.config["RADIUS_CERT_KEY_PASSWORD"]).encode()


def _file(name: str) -> Path:
    path = _root() / name
    if path.is_symlink():
        raise ValueError("Certificate files must not be symbolic links")
    return path


def _protocol_ready() -> bool:
    marker = _file(".netadmin-control")
    return (
        marker.exists()
        and marker.read_text(encoding="ascii").strip() == "1"
        and b"radius-supervisor.sh" in Path("/proc/1/cmdline").read_bytes()
    )


def _inventory() -> dict[str, Any]:
    ca = x509.load_pem_x509_certificate(_file("ca.pem").read_bytes())
    server = x509.load_pem_x509_certificate(_file("server.pem").read_bytes())
    reason = ""
    if not current_app.config["RADIUS_CERT_MANAGEMENT"]:
        reason = "Certificate management is not enabled on this agent."
    elif not _protocol_ready():
        reason = "Update the RADIUS service image to enable certificate activation."
    elif not _file("ca.key").exists():
        reason = "The CA signing key is not available. Renew or revoke through your external CA."
    else:
        key = load_signing_key(_file("ca.key").read_bytes(), _password())
        if not key_matches(ca, key):
            raise ValueError("CA key mismatch")
        ca.verify_directly_issued_by(ca)
        server.verify_directly_issued_by(ca)
    crl_path = _file("netadmin-crl.pem")
    crl = x509.load_pem_x509_crl(crl_path.read_bytes()) if crl_path.exists() else None
    return {
        "available": True,
        "ca": certificate_info(ca),
        "server": certificate_info(server),
        "can_manage": not reason,
        "reason": reason,
        "revoked_count": len(crl) if crl is not None else 0,
        "crl_expires": crl.next_update_utc.isoformat()
        if crl is not None and crl.next_update_utc
        else None,
        "has_crl": crl is not None,
    }


def _status() -> Any:
    try:
        return jsonify(_inventory())
    except (OSError, ValueError, TypeError, x509.InvalidVersion, InvalidSignature):
        return jsonify(
            {
                "available": False,
                "reason": "RADIUS certificates are unavailable or could not be verified.",
            }
        )


def _restart() -> None:
    """Wait for the service wrapper to acknowledge a fresh daemon process."""
    token = secrets.token_hex(24)
    request = _file(".netadmin-restart-request")
    request.write_text(token, encoding="ascii")
    request.chmod(0o600)
    command = list(current_app.config["RADIUS_CERT_RESTART"])
    if not command:
        raise ValueError("Certificate restart command is not configured")
    subprocess.run(command, check=True, capture_output=True, timeout=5)  # noqa: S603
    result = _file(".netadmin-restart-result")
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if result.exists() and result.read_text(encoding="ascii").strip() == token:
            return
        time.sleep(0.1)
    raise RuntimeError("RADIUS did not acknowledge certificate activation")


def _install(changes: dict[str, str]) -> None:
    server_stat = _file("server.pem").stat()
    restart_attempted = False

    def validate_and_activate() -> None:
        nonlocal restart_attempted
        for name in changes:
            path = _file(name)
            path.chmod(0o600 if name == "ca.key" else 0o640)
            os.chown(path, server_stat.st_uid, server_stat.st_gid)
        subprocess.run(["/usr/sbin/radiusd", "-XC"], check=True, capture_output=True, timeout=20)
        restart_attempted = True
        _restart()

    try:
        validated_transaction(
            {_file(name): value for name, value in changes.items()},
            validate_and_activate,
            [],
            allowed_roots=(_root(),),
        )
    except Exception:
        if restart_attempted:
            _restart()  # The files have been rolled back; activate the original identity again.
        raise


def _operate() -> Any:
    body = json_object()
    action = str(body.get("action", ""))
    if action not in {"renew-server", "revoke-server", "renew-ca", "retire-ca", "refresh-crl"}:
        return jsonify({"error": "Unknown certificate operation"}), 400
    try:
        if not _root().is_dir():
            raise ValueError("Certificate directory missing")
        with _file(".netadmin-cert-lock").open("a", encoding="ascii") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            status = _inventory()
            if not status["can_manage"]:
                return jsonify({"error": status["reason"]}), 409
            if any(
                body.get(f"expected_{kind}") != status[kind]["fingerprint"]
                for kind in ("ca", "server")
            ):
                return jsonify(
                    {"error": "Certificates changed. Refresh the page before continuing."}
                ), 409
            if action == "retire-ca" and body.get("confirmation") != "REPLACE CA":
                return jsonify({"error": "Type REPLACE CA to confirm retirement."}), 400
            crl = _file("netadmin-crl.pem")
            changes = certificate_changes(
                _file("ca.pem").read_bytes(),
                _file("ca.key").read_bytes(),
                _file("server.pem").read_bytes(),
                crl.read_bytes() if crl.exists() else None,
                _password(),
                action,
            )
            _install(changes)
            return jsonify({"action": action, "status": "applied"})
    except (
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
        x509.ExtensionNotFound,
        InvalidSignature,
    ):
        return jsonify(
            {
                "error": "Certificate operation failed. Previous files were retained or restored; "
                "check the RADIUS service status."
            }
        ), 502


def _download(kind: str) -> Any:
    names = {"ca": "ca.pem", "server": "server.pem", "crl": "netadmin-crl.pem"}
    if kind not in names:
        return jsonify({"error": "Unknown public certificate document"}), 404
    try:
        data = _file(names[kind]).read_bytes()
        if kind == "crl":
            public = x509.load_pem_x509_crl(data).public_bytes(PEM)
        else:
            public = x509.load_pem_x509_certificate(data).public_bytes(PEM)
        return jsonify({"pem": public.decode("ascii")})
    except (OSError, ValueError):
        return jsonify({"error": "Public certificate document unavailable"}), 404


def register_certificates(app: Flask) -> None:
    """Keep certificate administration within the authenticated service agent."""
    app.config.update(
        RADIUS_CERT_DIR=configured_path("RADIUS_CERT_DIR", "/etc/raddb/certs"),
        RADIUS_CERT_MANAGEMENT=os.getenv("RADIUS_CERT_MANAGEMENT", "false") == "true",
        RADIUS_CERT_KEY_PASSWORD=os.getenv("RADIUS_CERT_KEY_PASSWORD", "whatever"),
        RADIUS_CERT_RESTART=os.getenv("RADIUS_CERT_RESTART_COMMAND", "kill -USR1 1").split(),
    )
    app.add_url_rule("/certificates", view_func=_status, methods=["GET"])
    app.add_url_rule("/certificates", view_func=_operate, methods=["POST"])
    app.add_url_rule("/certificates/<kind>", view_func=_download, methods=["GET"])
