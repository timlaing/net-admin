"""Validate enrollment material and activate connections without exposing secrets."""

from __future__ import annotations

import os
import secrets
import shutil
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from netadmin.config import Settings
from netadmin.connections import (
    configuration_errors,
    connection_extensions,
    connection_values,
    env_key,
    settings_with_connections,
)
from netadmin.pairing_credentials import environment_uses
from netadmin.pairing_exchange import PORTS, claim
from netadmin.preferences import env_path, write_env_file


def validate_payload(payload: dict[str, Any]) -> list[str]:
    """Reject unexpected services, multiline tokens and incomplete credential material."""
    services = payload.get("services")
    if (
        payload.get("schema") != 1
        or not isinstance(services, list)
        or not services
        or any(name not in PORTS for name in services)
    ):
        raise ValueError("Invalid installed service selection")
    for field in ("token", "management_token"):
        value = payload.get(field)
        if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
            raise ValueError("Invalid enrollment token")
    if len(payload["token"]) < 32 or ("ca" in services and len(payload["management_token"]) < 32):
        raise ValueError("Enrollment token is too short")
    for field in ("ca", "certificate", "key"):
        if not isinstance(payload.get(field), str):
            raise ValueError("Invalid credential material")
    return services


def validate_identity(payload: dict[str, Any]) -> None:
    """Check issuer signature, CA scope, validity, client usage and matching private key."""
    authority = x509.load_pem_x509_certificate(payload["ca"].encode())
    certificate = x509.load_pem_x509_certificate(payload["certificate"].encode())
    key = serialization.load_pem_private_key(payload["key"].encode(), password=None)
    now = datetime.now(UTC)
    if not authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Transport authority must be a CA")
    if not all(
        cert.not_valid_before_utc <= now < cert.not_valid_after_utc
        for cert in (authority, certificate)
    ):
        raise ValueError("Transport certificate is expired or not yet valid")
    certificate.verify_directly_issued_by(authority)
    if (
        ExtendedKeyUsageOID.CLIENT_AUTH
        not in certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ):
        raise ValueError("Client authentication certificate required")
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature and not usage.key_agreement:
        raise ValueError("Client certificate needs signature or key agreement usage")
    if key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("Client key does not match certificate")


def enroll(settings: Settings, code: str) -> dict[str, Any]:
    """Stage validated private credentials and activate the paired connections together."""
    payload = claim(code)
    services = validate_payload(payload)
    validate_identity(payload)
    target = env_path().parent / "pki" / ("paired-" + secrets.token_hex(16))
    target.mkdir(parents=True, mode=0o700)
    try:
        (target / ".managed").touch(mode=0o600)
        for field, name in (("ca", "ca.crt"), ("certificate", "client.crt"), ("key", "client.key")):
            path = target / name
            with os.fdopen(
                os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
            ) as handle:
                handle.write(payload[field])
        values = connection_values(settings)
        values.update(
            agent_token=payload["token"],
            agent_ca=str(target / "ca.crt"),
            agent_cert=str(target / "client.crt"),
            agent_key=str(target / "client.key"),
        )
        for name, port in PORTS.items():
            flag = "radius_admin_enabled" if name == "radius" else f"{name}_enabled"
            values[flag] = str(name in services).lower()
            if name in services:
                values[f"{name}_agent_url"] = f"https://{payload['address']}:{port}"
        values["dns_use_agent"] = str("dns" in services).lower()
        if "dns" not in services:
            values["dns_config_path"] = ""
        values["ca_management_token"] = payload["management_token"]
        if configuration_errors(values):
            raise ValueError("Imported connections are invalid")
        replacements = connection_extensions(settings_with_connections(settings, values))
        write_env_file({env_key(field): value for field, value in values.items()})
        return replacements
    except BaseException:
        if not environment_uses(target):
            shutil.rmtree(target)
        raise
