"""Restricted step CLI adapter; credentials and private keys remain agent-local."""

from __future__ import annotations

import os
import ssl
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from netadmin.agents.common import configured_path


def run_step(arguments: list[str], *, password: bytes | None = None) -> str:
    """Run fixed subcommands without shell expansion, prompts, or logged secrets."""
    result = subprocess.run(  # noqa: S603
        ["/usr/local/bin/step", *arguments],
        stdin=subprocess.DEVNULL if password is None else None,
        input=password.decode("utf-8") if password is not None else None,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    return result.stdout.strip()


def connection_flags() -> list[str]:
    """Always verify the configured HTTPS authority against a pinned root file."""
    url, root = connection_settings()
    return ["--ca-url", url, "--root", str(root)]


def connection_settings() -> tuple[str, Path]:
    """Validate endpoint configuration before any network request."""
    url = os.environ["STEP_CA_URL"].rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or any((parsed.username, parsed.query, parsed.fragment, parsed.path))
    ):
        raise ValueError("STEP_CA_URL must be an HTTPS origin")
    return url, configured_path("STEP_CA_ROOT", "/trust/root_ca.crt")


def fetch_crl() -> x509.CertificateRevocationList:
    """Read authoritative public revocation state over the pinned HTTPS connection."""
    url, root = connection_settings()
    context = ssl.create_default_context(cafile=str(root))
    with httpx.Client(verify=context, trust_env=False) as client:
        response = client.get(url + "/1.0/crl", timeout=10)
        response.raise_for_status()
    return x509.load_der_x509_crl(response.content)


def issued_matches_csr(pem: bytes, csr: x509.CertificateSigningRequest) -> x509.Certificate:
    """Reject incomplete chains and certificates for another key or identity."""
    certificates = x509.load_pem_x509_certificates(pem)
    certificate = certificates[0]
    form = PublicFormat.SubjectPublicKeyInfo
    if certificate.public_key().public_bytes(Encoding.DER, form) != csr.public_key().public_bytes(
        Encoding.DER, form
    ):
        raise ValueError("Issued public key does not match CSR")
    from cryptography.x509.oid import NameOID  # pylint: disable=import-outside-toplevel

    if certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    ) != csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        raise ValueError("Issued common name does not match CSR")
    try:
        names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return certificate
    if certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value != names:
        raise ValueError("Issued SANs do not match CSR")
    return certificate


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


def signing_configuration() -> None:
    """Reject deterministic local configuration errors before marking an attempt."""
    _, root = connection_settings()
    provisioner_flags()
    x509.load_pem_x509_certificate(root.read_bytes())
    password = configured_path("STEP_CA_PASSWORD_FILE", "/run/secrets/provisioner-password")
    if not password.is_file() or not os.access(password, os.R_OK):
        raise ValueError("Provisioner credential file is unavailable")


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


def renew_certificate(bundle: Path, key: Path, output: Path, password: bytes) -> None:
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
            "/dev/stdin",
            *connection_flags(),
        ],
        password=password,
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
    try:
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
    except subprocess.CalledProcessError as error:
        if (
            "is already revoked" not in (error.stderr or "")
            and fetch_crl().get_revoked_certificate_by_serial_number(serial) is None
        ):
            raise


def validate_server_chain(pem: bytes, root_pem: bytes) -> list[x509.Certificate]:
    """Verify an ordered leaf/intermediate chain ending at the pinned root."""
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
            _validate_issuer(cert, index)
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


def _validate_issuer(certificate: x509.Certificate, index: int) -> None:
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not constraints.ca or (
        constraints.path_length is not None and index - 1 > constraints.path_length
    ):
        raise ValueError("Invalid issuing CA constraints")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not usage.key_cert_sign:
        raise ValueError("Issuing CA cannot sign certificates")


def failure_category(error: Exception) -> str:
    """Diagnose failures without exposing exception text, arguments, tokens or key bytes."""
    if isinstance(error, subprocess.TimeoutExpired):
        return "CA command timed out"
    if isinstance(error, subprocess.CalledProcessError):
        return f"CA command failed (exit {error.returncode})"
    if isinstance(error, httpx.HTTPError):
        return "CA transport or HTTP response failure"
    if isinstance(error, OSError):
        return "local filesystem or permission failure"
    if isinstance(error, KeyError):
        return "missing configuration"
    return (
        "certificate or configuration validation failure"
        if isinstance(error, ValueError | x509.ExtensionNotFound)
        else "service activation or unexpected runtime failure"
    )
