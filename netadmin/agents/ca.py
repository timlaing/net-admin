"""Restricted step-ca registration agent; never mounts CA signing keys."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess  # nosec B404
import uuid
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from flask import Flask, current_app, jsonify

from netadmin.agents.common import configured_path, create_agent, json_object
from netadmin.services.radius_certificates import PEM, certificate_info, certificate_options
from netadmin.services.step_ca import (
    failure_category,
    fetch_crl,
    issued_matches_csr,
    revoke_certificate,
    sign_csr,
    validate_csr,
)

CERTIFICATE_FILE = "certificate.pem"
UNKNOWN_CERTIFICATE = "Unknown certificate"
REVOCATION_ERROR = "CA revocation failed; check CA state before retrying"


def _root() -> Path:
    return Path(current_app.config["CA_DATA_DIR"])


def _inventory() -> Any:
    certificates = []
    for path in sorted(_root().glob("*/certificate.pem")):
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
        except (OSError, ValueError):
            current_app.logger.warning(
                "Ignoring incomplete certificate record: %s", path.parent.name
            )
            continue
        certificates.append(
            {
                **certificate_info(cert),
                "id": path.parent.name,
                "revocation_pending": (
                    _root() / "revocations" / f"{cert.serial_number:x}.pending"
                ).exists(),
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
        csr = validate_csr(pem)
        days = certificate_options({"days": body.get("days", 365)})["days"]
        digest = hashlib.sha256(csr.public_bytes(PEM) + str(days).encode("ascii")).hexdigest()
        identifier = body.get("request_id", digest[:32])
        if (
            not isinstance(identifier, str)
            or len(identifier) != 32
            or any(char not in "0123456789abcdef" for char in identifier)
        ):
            raise ValueError("Invalid issuance request ID")
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid CSR, validity or request ID"}), 400
    try:
        # UUID.hex constructs the path component from a parsed 128-bit identifier.
        directory = _root() / uuid.UUID(hex=identifier).hex
        directory.mkdir(mode=0o700, exist_ok=True)
        with (directory / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return _issue_record(directory, pem, days, digest)
    except (OSError, ValueError, x509.ExtensionNotFound, subprocess.SubprocessError) as error:
        # Raw subprocess tracebacks can contain tokens and credential material.
        current_app.logger.error("CA issuance failed: %s", failure_category(error))  # NOSONAR
        return jsonify(
            {"error": "CA issuance failed; inspect the agent inventory before retrying"}
        ), 502


def _issue_record(directory: Path, pem: str, days: int, digest: str) -> Any:
    """Publish only complete certificates and never automatically re-sign an uncertain request."""
    record = directory / "request.json"
    if record.exists() and json.loads(record.read_text())["digest"] != digest:
        return jsonify({"error": "Request ID was already used with another CSR or lifetime"}), 409
    request = directory / "request.pem"
    output = directory / CERTIFICATE_FILE
    candidate = directory / "signing.pem"
    attempted = directory / "attempted"
    csr = validate_csr(pem)
    if not output.exists():
        if candidate.exists():
            # Recover a complete response left behind by a crash after signing.
            issued_matches_csr(candidate.read_bytes(), csr)
            os.replace(candidate, output)
        elif attempted.exists():
            return jsonify(
                {"error": "Issuance outcome is uncertain; reconcile CA records before retrying"}
            ), 409
        else:
            _durable_write(record, json.dumps({"digest": digest}))
            _durable_write(request, pem)
            _durable_write(attempted, "1")
            sign_csr(request, candidate, days)
            issued_matches_csr(candidate.read_bytes(), csr)
            os.replace(candidate, output)
    certificate = issued_matches_csr(output.read_bytes(), csr)
    return jsonify(
        {
            "id": directory.name,
            "pem": output.read_text(),
            "certificate": certificate_info(certificate),
        }
    ), 201


def _durable_write(path: Path, content: str) -> None:
    """Publish local operation state atomically before/after authority side effects."""
    candidate = path.with_suffix(path.suffix + ".tmp")
    with candidate.open("w", encoding="ascii") as record:
        record.write(content)
        record.flush()
        os.fsync(record.fileno())
    os.replace(candidate, path)


def _revoke(identifier: str) -> Any:
    if len(identifier) != 32 or any(char not in "0123456789abcdef" for char in identifier):
        return jsonify({"error": UNKNOWN_CERTIFICATE}), 404
    path = _root() / identifier
    if not (path / CERTIFICATE_FILE).is_file():
        return jsonify({"error": UNKNOWN_CERTIFICATE}), 404
    reason = json_object().get("reason", "0")
    if str(reason) not in {"0", "1", "3", "4", "5", "9"}:
        return jsonify({"error": "Invalid revocation reason"}), 400
    try:
        cert = x509.load_pem_x509_certificate((path / CERTIFICATE_FILE).read_bytes())
        _record_revocation(cert.serial_number, int(reason))
        return jsonify({"status": "revoked"})
    except (OSError, ValueError, httpx.HTTPError, subprocess.SubprocessError) as error:
        # Raw subprocess tracebacks can contain tokens and credential material.
        current_app.logger.error("CA revocation failed: %s", failure_category(error))  # NOSONAR
        return jsonify({"error": REVOCATION_ERROR}), 502


def _record_revocation(serial: int, reason: int) -> None:
    """Serialize revocation by serial, including certificates renewed outside this agent."""
    directory = _root() / "revocations"
    directory.mkdir(exist_ok=True, mode=0o700)
    path = directory / format(serial, "x")
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            pending = path.with_suffix(".pending")
            _durable_write(pending, str(reason))
            revoke_certificate(serial, reason)
            _durable_write(path, str(reason))
            pending.unlink(missing_ok=True)


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
    except (OSError, ValueError, httpx.HTTPError, subprocess.SubprocessError) as error:
        # Raw subprocess tracebacks can contain tokens and credential material.
        current_app.logger.error("CA revocation failed: %s", failure_category(error))  # NOSONAR
        return jsonify({"error": REVOCATION_ERROR}), 502


def _download(identifier: str) -> Any:
    if identifier == "root":
        path = configured_path("STEP_CA_ROOT", "/trust/root_ca.crt")
    elif len(identifier) == 32 and all(char in "0123456789abcdef" for char in identifier):
        path = _root() / identifier / CERTIFICATE_FILE
    else:
        return jsonify({"error": UNKNOWN_CERTIFICATE}), 404
    if not path.is_file():
        return jsonify({"error": UNKNOWN_CERTIFICATE}), 404
    try:
        certs = x509.load_pem_x509_certificates(path.read_bytes())
        return jsonify({"pem": b"".join(cert.public_bytes(PEM) for cert in certs).decode("ascii")})
    except (OSError, ValueError):
        return jsonify({"error": "Certificate record unavailable"}), 502


def _crl() -> Any:
    """Fetch public revocation data over the pinned CA TLS connection."""
    try:
        crl = fetch_crl()
        return jsonify({"pem": crl.public_bytes(PEM).decode("ascii")})
    except (OSError, ValueError, KeyError, httpx.HTTPError) as error:
        current_app.logger.warning("CRL retrieval failed: %s", failure_category(error))
        return jsonify(
            {"error": "CRL unavailable; check CA configuration and CRL publication"}
        ), 502


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
