"""step-ca enrolment and staged renewal for the RADIUS agent."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from netadmin.agents.common import configured_path
from netadmin.services.agents import AgentClient
from netadmin.services.radius_certificates import (
    PEM,
    certificate_options,
    key_matches,
    load_signing_key,
    private_pem,
    replacement_key,
)
from netadmin.services.step_ca import renew_certificate, validate_server_chain

SERVER_PEM = "server.pem"


def enabled() -> bool:
    """Select the backend explicitly; missing configuration must never downgrade it."""
    return os.getenv("RADIUS_CERT_BACKEND", "local") == "step-ca"


def _client() -> AgentClient:
    return AgentClient(
        os.environ["RADIUS_CA_AGENT_URL"],
        os.environ["NETADMIN_AGENT_TOKEN"],
        configured_path("RADIUS_CA_AGENT_CA", "/ca-agent-client/ca.crt"),
        configured_path("RADIUS_CA_AGENT_CERT", "/ca-agent-client/client.crt"),
        configured_path("RADIUS_CA_AGENT_KEY", "/ca-agent-client/client.key"),
    )


def trusted_root() -> bytes:
    """Use an operator-pinned root, never a root received from a signing response."""
    return configured_path("STEP_CA_ROOT", "/trust/root_ca.crt").read_bytes()


def managed(bundle: bytes) -> bool:
    """Distinguish pre-migration identities from enrolled step-ca identities."""
    try:
        validate_server_chain(bundle, trusted_root())
        return True
    except (ValueError, InvalidSignature, x509.ExtensionNotFound):
        return False


def _enrollment_identity(
    previous: x509.Certificate, options: dict[str, Any]
) -> tuple[x509.Name, x509.SubjectAlternativeName]:
    common_name = options.get("common_name")
    if common_name is None:
        names = previous.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1:
            raise ValueError("Specify a common name for step-ca enrolment")
        common_name = names[0].value
    sans = options.get("sans")
    if sans is None:
        try:
            sans = previous.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound as error:
            raise ValueError("Specify SANs for step-ca enrolment") from error
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]), sans


def changes(directory: Path, password: bytes, body: dict[str, Any]) -> dict[str, str]:
    """Prepare new files without changing the active RADIUS identity."""
    root = trusted_root()
    bundle = (directory / SERVER_PEM).read_bytes()
    previous = x509.load_pem_x509_certificate(bundle)
    action = body["action"]
    if action == "enroll-step-ca":
        if body.get("confirmation") != "STEP CA":
            raise ValueError("Confirm replacement of RADIUS CA trust with STEP CA")
        options = certificate_options(body)
        key = replacement_key(previous)
        subject, sans = _enrollment_identity(previous, options)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(sans, False)
            .sign(key, hashes.SHA256())
        )
        result = _client().post(
            "certificates",
            {
                "csr": csr.public_bytes(PEM).decode("ascii"),
                "days": options.get("days", 1),
            },
            timeout=60,
        )
        pem = result["pem"].encode("ascii")
        expected_subject = subject
        expected_sans = sans
    elif action == "renew-server":
        validate_server_chain(bundle, root)
        key = load_signing_key(bundle, password)
        with tempfile.TemporaryDirectory(prefix="netadmin-renew-") as temporary:
            stage = Path(temporary)
            source, output = stage / SERVER_PEM, stage / "renewed.pem"
            source.write_bytes(
                b"".join(cert.public_bytes(PEM) for cert in x509.load_pem_x509_certificates(bundle))
            )
            keyfile = stage / "key.pem"
            keyfile.write_bytes(private_pem(key, password))
            keyfile.chmod(0o600)
            source.chmod(0o600)
            renew_certificate(source, keyfile, output, password)
            pem = output.read_bytes()
        expected_subject = previous.subject
        expected_sans = previous.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    else:
        raise ValueError("Local CA operations are disabled for step-ca certificates")
    chain = validate_server_chain(pem, root)
    leaf = chain[0]
    _validate_new_usage(leaf)
    if not key_matches(leaf, key) or leaf.subject != expected_subject:
        raise ValueError("Issued certificate does not match the requested identity")
    if leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value != expected_sans:
        raise ValueError("Issued SANs differ from the requested SANs")
    # The root is a trust anchor; only the leaf and intermediates are presented by RADIUS.
    public_chain = b"".join(cert.public_bytes(PEM) for cert in chain[:-1])
    return {
        SERVER_PEM: (private_pem(key, password) + public_chain).decode("ascii"),
        "ca.pem": root.decode("ascii"),
        f"previous-server-{previous.serial_number:x}.crt": previous.public_bytes(PEM).decode(
            "ascii"
        ),
    }


def _validate_new_usage(leaf: x509.Certificate) -> None:
    # Newly activated identities must support signed TLS handshakes (including TLS 1.3).
    # Inspecting the old identity above remains permissive so legacy keys can be renewed.
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not usage.digital_signature:
            raise ValueError("New server certificate KeyUsage must permit digital signatures")


def renewal_due(bundle: bytes) -> bool:
    """Renew after two-thirds of the certificate lifetime; retry failures next poll."""
    cert = x509.load_pem_x509_certificate(bundle)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    return datetime.now(UTC) >= cert.not_valid_before_utc + lifetime * (2 / 3)
