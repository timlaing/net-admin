"""Restricted step-ca registration agent; never mounts CA signing keys."""

from __future__ import annotations

import fcntl
import os
import ssl
import subprocess  # nosec B404
import uuid
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from flask import Flask, current_app, jsonify

from netadmin.agents.common import configured_path, create_agent, json_object
from netadmin.services.radius_certificates import PEM, certificate_info, certificate_options
from netadmin.services.step_ca import revoke_certificate, sign_csr, validate_csr


def _root() -> Path:
    return Path(current_app.config["CA_DATA_DIR"])


def _inventory() -> Any:
    certificates = []
    for path in sorted(_root().glob("*/certificate.pem")):
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        certificates.append(
            {
                **certificate_info(cert),
                "id": path.parent.name,
                "revoked": (path.parent / "revoked").exists()
                or (_root() / "revocations" / format(cert.serial_number, "x")).exists(),
            }
        )
    return jsonify({"certificates": certificates})


def _issue() -> Any:
    body = json_object()
    try:
        pem = body.get("csr", "")
        if not isinstance(pem, str):
            raise ValueError("CSR must be PEM text")
        validate_csr(pem)
        days = certificate_options({"days": body.get("days", 365)})["days"]
    except (ValueError, TypeError, UnicodeError):
        return jsonify({"error": "Invalid CSR or validity"}), 400
    # Each operation retains its CSR and output even if the HTTP connection drops.
    directory = _root() / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    request = directory / "request.pem"
    request.write_text(pem, encoding="ascii")
    output = directory / "certificate.pem"
    try:
        sign_csr(request, output, days)
        certificate = x509.load_pem_x509_certificate(output.read_bytes())
        return jsonify(
            {
                "id": directory.name,
                "pem": output.read_text(),
                "certificate": certificate_info(certificate),
            }
        ), 201
    except (OSError, ValueError, subprocess.SubprocessError):
        return jsonify(
            {"error": "CA issuance failed; inspect the agent inventory before retrying"}
        ), 502


def _revoke(identifier: str) -> Any:
    if len(identifier) != 32 or any(char not in "0123456789abcdef" for char in identifier):
        return jsonify({"error": "Unknown certificate"}), 404
    path = _root() / identifier
    if not (path / "certificate.pem").is_file():
        return jsonify({"error": "Unknown certificate"}), 404
    reason = json_object().get("reason", "0")
    if str(reason) not in {"0", "1", "3", "4", "5", "9"}:
        return jsonify({"error": "Invalid revocation reason"}), 400
    try:
        cert = x509.load_pem_x509_certificate((path / "certificate.pem").read_bytes())
        _record_revocation(cert.serial_number, int(reason))
        return jsonify({"status": "revoked"})
    except (OSError, ValueError, subprocess.SubprocessError):
        return jsonify({"error": "CA revocation failed; check CA state before retrying"}), 502


def _record_revocation(serial: int, reason: int) -> None:
    """Serialize revocation by serial, including certificates renewed outside this agent."""
    directory = _root() / "revocations"
    directory.mkdir(exist_ok=True, mode=0o700)
    path = directory / format(serial, "x")
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            revoke_certificate(serial, reason)
            with path.open("w", encoding="ascii") as record:
                record.write(str(reason))
                record.flush()
                os.fsync(record.fileno())


def _revoke_serial() -> Any:
    body = json_object()
    serial = body.get("serial", "")
    reason = body.get("reason", "0")
    if not isinstance(serial, str):
        return jsonify({"error": "Serial must be hexadecimal text"}), 400
    serial = serial.lower().removeprefix("0x")
    if (
        not 1 <= len(serial) <= 40
        or any(char not in "0123456789abcdef" for char in serial)
        or int(serial, 16) == 0
        or str(reason) not in {"0", "1", "3", "4", "5", "9"}
    ):
        return jsonify({"error": "Invalid hexadecimal serial or reason"}), 400
    try:
        _record_revocation(int(serial, 16), int(reason))
        return jsonify({"status": "revoked"})
    except (OSError, ValueError, subprocess.SubprocessError):
        return jsonify({"error": "CA revocation failed; check CA state before retrying"}), 502


def _download(identifier: str) -> Any:
    if identifier == "root":
        path = configured_path("STEP_CA_ROOT", "/trust/root_ca.crt")
    elif len(identifier) == 32 and all(char in "0123456789abcdef" for char in identifier):
        path = _root() / identifier / "certificate.pem"
    else:
        return jsonify({"error": "Unknown certificate"}), 404
    if not path.is_file():
        return jsonify({"error": "Unknown certificate"}), 404
    certs = x509.load_pem_x509_certificates(path.read_bytes())
    return jsonify({"pem": b"".join(cert.public_bytes(PEM) for cert in certs).decode("ascii")})


def _crl() -> Any:
    """Fetch public revocation data over the pinned CA TLS connection."""
    from netadmin.services.step_ca import connection_flags  # pylint: disable=import-outside-toplevel

    flags = connection_flags()
    try:
        context = ssl.create_default_context(cafile=flags[3])
        with httpx.Client(verify=context, trust_env=False) as client:
            response = client.get(flags[1] + "/1.0/crl", timeout=10)
            response.raise_for_status()
        crl = x509.load_der_x509_crl(response.content)
        return jsonify({"pem": crl.public_bytes(PEM).decode("ascii")})
    except (OSError, ValueError, httpx.HTTPError):
        return jsonify({"error": "CRL unavailable; enable CRLs on step-ca"}), 502


def create_ca_agent() -> Flask:
    """Create a token/mTLS-protected registration service."""
    app = create_agent(__name__)
    app.config.update(CA_DATA_DIR=configured_path("CA_DATA_DIR", "/data"), MAX_CONTENT_LENGTH=65536)
    root = Path(app.config["CA_DATA_DIR"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    app.add_url_rule("/health", view_func=lambda: jsonify({"status": "ok"}), methods=["GET"])
    app.add_url_rule("/revoke", view_func=_revoke_serial, methods=["POST"])
    app.add_url_rule("/crl", view_func=_crl, methods=["GET"])
    app.add_url_rule("/certificates", view_func=_inventory, methods=["GET"])
    app.add_url_rule("/certificates", view_func=_issue, methods=["POST"])
    app.add_url_rule("/certificates/<identifier>/revoke", view_func=_revoke, methods=["POST"])
    app.add_url_rule("/certificates/<identifier>", view_func=_download, methods=["GET"])
    return app
