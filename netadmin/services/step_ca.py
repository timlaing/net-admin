"""Restricted step CLI adapter; credentials and private keys remain agent-local."""

from __future__ import annotations

import os
import subprocess  # nosec B404
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from netadmin.agents.common import configured_path


def run_step(arguments: list[str]) -> str:
    """Run fixed subcommands without shell expansion, prompts, or logged secrets."""
    result = subprocess.run(  # noqa: S603
        ["/usr/local/bin/step", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )
    return result.stdout.strip()


def connection_flags() -> list[str]:
    """Always verify the configured HTTPS authority against a pinned root file."""
    url = os.environ["STEP_CA_URL"].rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query:
        raise ValueError("STEP_CA_URL must be an HTTPS URL")
    return ["--ca-url", url, "--root", str(configured_path("STEP_CA_ROOT", "/trust/root_ca.crt"))]


def provisioner_flags() -> list[str]:
    """Read only the provisioner credential, never the authority signing key."""
    name = os.environ["STEP_CA_PROVISIONER"]
    if not name or name.startswith("-"):
        raise ValueError("Invalid provisioner name")
    return [
        "--provisioner",
        name,
        "--provisioner-password-file",
        str(configured_path("STEP_CA_PASSWORD_FILE", "/run/secrets/provisioner-password")),
    ]


def validate_csr(pem: str) -> x509.CertificateSigningRequest:
    """Reject malformed requests, CA privileges and unsupported public keys."""
    if len(pem) > 32768:
        raise ValueError("CSR is too large")
    csr = x509.load_pem_x509_csr(pem.encode("ascii"))
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")
    key = csr.public_key()
    if not isinstance(key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
        raise ValueError("Only RSA and EC keys are supported")
    if key.key_size < (2048 if isinstance(key, rsa.RSAPublicKey) else 256):
        raise ValueError("CSR key is too weak")
    for extension in csr.extensions:
        if isinstance(extension.value, x509.BasicConstraints) and extension.value.ca:
            raise ValueError("CA certificates cannot be requested")
        if isinstance(extension.value, x509.KeyUsage) and (
            extension.value.key_cert_sign or extension.value.crl_sign
        ):
            raise ValueError("CA signing usages cannot be requested")
    return csr


def sign_csr(request: Path, output: Path, days: int) -> None:
    """Issue through a dedicated provisioner; server templates enforce final policy."""
    run_step(
        [
            "ca",
            "sign",
            str(request),
            str(output),
            "--not-after",
            f"{days * 24}h",
            *connection_flags(),
            *provisioner_flags(),
        ]
    )


def renew_certificate(bundle: Path, key: Path, output: Path, password_file: Path) -> None:
    """Stage renewal using the existing key; X5C supports serverAuth-only leaves."""
    run_step(
        [
            "ca",
            "renew",
            str(bundle),
            str(key),
            "--out",
            str(output),
            "--force",
            "--mtls=false",
            "--password-file",
            str(password_file),
            *connection_flags(),
        ]
    )


def revoke_certificate(serial: int, reason: int) -> None:
    """Authorize revocation with a short-lived token; never return it to callers."""
    token = run_step(
        [
            "ca",
            "token",
            str(serial),
            "--revoke",
            *connection_flags(),
            *provisioner_flags(),
        ]
    )
    run_step(
        [
            "ca",
            "revoke",
            str(serial),
            "--reasonCode",
            str(reason),
            "--token",
            token,
            *connection_flags(),
        ]
    )


def validate_server_chain(pem: bytes, root_pem: bytes) -> list[x509.Certificate]:
    """Verify an ordered leaf/intermediate chain ending at the pinned root."""
    from datetime import UTC, datetime  # pylint: disable=import-outside-toplevel

    chain = x509.load_pem_x509_certificates(pem)
    root = x509.load_pem_x509_certificate(root_pem)
    if not chain or len(chain) > 6:
        raise ValueError("Invalid server chain")
    if chain[-1] != root:
        chain.append(root)
    now = datetime.now(UTC)
    for index, cert in enumerate(chain):
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("Certificate chain is not currently valid")
        if index:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca or (
                constraints.path_length is not None and index - 1 > constraints.path_length
            ):
                raise ValueError("Invalid issuing CA constraints")
        if index < len(chain) - 1:
            cert.verify_directly_issued_by(chain[index + 1])
    try:
        if chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Server certificate cannot be a CA")
    except x509.ExtensionNotFound:
        pass
    usages = chain[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.SERVER_AUTH not in usages:
        raise ValueError("Server certificate requires serverAuth")
    return chain
