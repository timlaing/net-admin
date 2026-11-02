"""X.509 operations for the RADIUS agent; private material never leaves the agent."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
PEM = serialization.Encoding.PEM


def certificate_options(body: dict[str, Any]) -> dict[str, Any]:
    """Validate optional server identity and lifetime at the agent boundary."""
    result: dict[str, Any] = {}
    if "days" in body:
        value = body["days"]
        if isinstance(value, bool) or not re.fullmatch(r"\d{1,4}", str(value)):
            raise ValueError("Validity must be a whole number of days")
        days = int(value)
        if not 1 <= days <= 3650:
            raise ValueError("Validity must be between 1 and 3650 days")
        result["days"] = days
    if "common_name" in body:
        result["common_name"] = _common_name(body["common_name"])
    if "sans" in body:
        value = body["sans"]
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError("SANs must be DNS names or IP addresses separated by commas")
        result["sans"] = _parse_sans(value)
    return result


def _common_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip() or len(name.encode()) > 64:
        raise ValueError("Common name must contain 1 to 64 bytes")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Invalid common name")
    return name.strip()


def _parse_sans(value: str) -> x509.SubjectAlternativeName:
    """Parse a bounded list of DNS names and IP addresses."""
    names: list[x509.GeneralName] = []
    for item in re.split(r"[,\s]+", value.strip()):
        if not item:
            continue
        try:
            names.append(x509.IPAddress(ip_address(item)))
        except ValueError:
            dns = item.encode("idna").decode("ascii").lower()
            labels = dns.removeprefix("*.").split(".")
            if len(dns) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError("Invalid DNS SAN") from None
            names.append(x509.DNSName(dns))
    if not names or len(names) > 100:
        raise ValueError("Specify between 1 and 100 SANs")
    return x509.SubjectAlternativeName(names)


def identity_options(certificate: x509.Certificate) -> dict[str, Any]:
    """Return editable public identity fields."""
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = ", ".join(str(name.value) for name in names)
        editable = ", ".join(
            str(name.value) for name in names if isinstance(name, x509.DNSName | x509.IPAddress)
        )
        unsupported = any(not isinstance(name, x509.DNSName | x509.IPAddress) for name in names)
    except x509.ExtensionNotFound:
        sans, editable, unsupported = "", "", False
    return {
        "common_name": str(common_names[0].value) if common_names else "",
        "sans": sans,
        "editable_sans": editable,
        "unsupported_sans": unsupported,
    }


def _signature_hash(key: SigningKey) -> hashes.SHA256 | hashes.SHA384 | hashes.SHA512:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.key_size > 384:
            return hashes.SHA512()
        if key.key_size > 256:
            return hashes.SHA384()
    return hashes.SHA256()


def replacement_key(certificate: x509.Certificate, *, is_ca: bool = False) -> SigningKey:
    """Preserve RSA strength and EC curves when replacing an existing identity."""
    public = certificate.public_key()
    if isinstance(public, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(public.curve)
    if isinstance(public, rsa.RSAPublicKey):
        return rsa.generate_private_key(
            public_exponent=65537, key_size=max(public.key_size, 3072 if is_ca else 2048)
        )
    raise ValueError("Only RSA and EC certificates are supported")


def certificate_info(certificate: x509.Certificate) -> dict[str, Any]:
    """Return public metadata suitable for the browser."""
    now = datetime.now(UTC)
    expires = certificate.not_valid_after_utc
    status = "Valid"
    if expires <= now:
        status = "Expired"
    elif certificate.not_valid_before_utc > now:
        status = "Not yet valid"
    elif expires - now < timedelta(days=30):
        status = "Expiring soon"
    return {
        **identity_options(certificate),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial": format(certificate.serial_number, "x"),
        "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(":"),
        "expires": expires.isoformat(),
        "valid_from": certificate.not_valid_before_utc.isoformat(),
        "status": status,
    }


def load_signing_key(pem: bytes, password: bytes) -> SigningKey:
    """Read encrypted bootstrap keys and operator-provisioned unencrypted keys."""
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise ValueError("Only RSA and EC signing keys are supported")
    return key


def key_matches(certificate: x509.Certificate, key: SigningKey) -> bool:
    """Compare public keys without returning private bytes."""
    encoding = serialization.Encoding.DER
    form = serialization.PublicFormat.SubjectPublicKeyInfo
    return certificate.public_key().public_bytes(encoding, form) == key.public_key().public_bytes(
        encoding, form
    )


def private_pem(key: SigningKey, password: bytes) -> bytes:
    """Protect generated keys with the configured EAP key password."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, encryption)


def issue_certificate(
    original: x509.Certificate,
    key: SigningKey,
    issuer: x509.Certificate,
    issuer_key: SigningKey,
    *,
    is_ca: bool = False,
    options: dict[str, Any] | None = None,
) -> x509.Certificate:
    """Preserve identity/SANs and policy extensions, refreshing serial and key IDs."""
    options = options or {}
    now = datetime.now(UTC)
    expires = now + timedelta(days=3650 if is_ca else options.get("days", 365))
    subject = original.subject
    if not is_ca and "common_name" in options:
        subject = x509.Name(
            [attr for attr in subject if attr.oid != NameOID.COMMON_NAME]
            + [x509.NameAttribute(NameOID.COMMON_NAME, options["common_name"])]
        )
    if not is_ca:
        expires = min(expires, issuer.not_valid_after_utc)
    if expires <= now:
        raise ValueError("Renew the expired CA before issuing a server certificate")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(original.subject if is_ca else issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(expires)
    )
    for extension in original.extensions:
        if extension.oid not in {
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            *({ExtensionOID.SUBJECT_ALTERNATIVE_NAME} if "sans" in options else set()),
        }:
            builder = builder.add_extension(extension.value, extension.critical)
    if "sans" in options and not is_ca:
        builder = builder.add_extension(options["sans"], _san_critical(original, subject))
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
    )
    return builder.sign(issuer_key, _signature_hash(issuer_key))


def _san_critical(original: x509.Certificate, subject: x509.Name) -> bool:
    if not subject:
        return True
    try:
        return original.extensions.get_extension_for_class(x509.SubjectAlternativeName).critical
    except x509.ExtensionNotFound:
        return False


def issue_crl(
    ca: x509.Certificate,
    key: SigningKey,
    existing: x509.CertificateRevocationList | None,
    revoked: x509.Certificate | None = None,
) -> x509.CertificateRevocationList:
    """Extend a signed CRL without losing previous revocations."""
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
    )
    number = 1
    if existing is not None:
        if existing.issuer != ca.subject or not existing.is_signature_valid(key.public_key()):
            raise ValueError("The existing CRL does not belong to this CA")
        for entry in existing:
            builder = builder.add_revoked_certificate(entry)
        try:
            number = (
                existing.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number + 1
            )
        except x509.ExtensionNotFound:
            number = 1
    if revoked is not None and (
        existing is None
        or existing.get_revoked_certificate_by_serial_number(revoked.serial_number) is None
    ):
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(now)
            .add_extension(x509.CRLReason(x509.ReasonFlags.cessation_of_operation), False)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    return builder.add_extension(x509.CRLNumber(number), False).sign(key, _signature_hash(key))


def certificate_changes(
    ca_pem: bytes,
    ca_key_pem: bytes,
    server_pem: bytes,
    crl_pem: bytes | None,
    password: bytes,
    action: str,
    options: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Prepare PEM files for one validated agent transaction."""
    if action not in {
        "create-server",
        "renew-server",
        "revoke-server",
        "renew-ca",
        "retire-ca",
        "refresh-crl",
    }:
        raise ValueError("Unknown certificate operation")
    ca = x509.load_pem_x509_certificate(ca_pem)
    server = x509.load_pem_x509_certificate(server_pem)
    ca_key = load_signing_key(ca_key_pem, password)
    if (
        not key_matches(ca, ca_key)
        or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ):
        raise ValueError("CA certificate and signing key are not a matching authority")
    ca.verify_directly_issued_by(ca)
    server.verify_directly_issued_by(ca)
    crl = x509.load_pem_x509_crl(crl_pem) if crl_pem else None
    changes: dict[str, bytes] = {}
    previous_server = server
    if action in {"renew-ca", "retire-ca"}:
        if action == "retire-ca":
            prefix = f"retired-{ca.serial_number:x}"
            changes[f"{prefix}-ca.pem"] = ca.public_bytes(PEM)
            changes[f"{prefix}-crl.pem"] = issue_crl(ca, ca_key, crl, server).public_bytes(PEM)
            ca_key = replacement_key(ca, is_ca=True)
            changes["ca.key"] = private_pem(ca_key, password)
            crl = None
        ca = issue_certificate(ca, ca_key, ca, ca_key, is_ca=True)
        changes["ca.pem"] = ca.public_bytes(PEM)
    if action not in {"renew-ca", "refresh-crl"}:
        server_key = replacement_key(server)
        if action == "create-server":
            if not options or not {"common_name", "sans"} <= options.keys():
                raise ValueError("New certificates require a common name and SANs")
            server = (
                x509.CertificateBuilder()
                .subject_name(server.subject)
                .issuer_name(ca.subject)
                .public_key(server_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
                .not_valid_after(datetime.now(UTC) + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(ca_key, _signature_hash(ca_key))
            )
        replacement = issue_certificate(server, server_key, ca, ca_key, options=options)
        changes[f"previous-server-{previous_server.serial_number:x}.crt"] = (
            previous_server.public_bytes(PEM)
        )
        changes["server.pem"] = private_pem(server_key, password) + replacement.public_bytes(PEM)
    revoked = server if action == "revoke-server" else None
    changes["netadmin-crl.pem"] = issue_crl(ca, ca_key, crl, revoked).public_bytes(PEM)
    return {name: value.decode("ascii") for name, value in changes.items()}
