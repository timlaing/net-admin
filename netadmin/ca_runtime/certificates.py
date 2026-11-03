"""Validated root and subordinate certificate construction."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from netadmin.services.radius_certificates import SigningKey, certificate_options

PEM = serialization.Encoding.PEM


class CAInputError(ValueError):
    """A bounded, safe-to-display validation message."""


SUBJECT_FIELDS = {
    "organization": NameOID.ORGANIZATION_NAME,
    "unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "country": NameOID.COUNTRY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "locality": NameOID.LOCALITY_NAME,
}


def _subject_attribute(field: str, value: Any) -> str:
    """Bound individual attributes before building X.509 subject objects."""
    if (
        not isinstance(value, str)
        or len(value.encode()) > 128
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise CAInputError(f"Invalid {field}")
    return value.strip()


def options(body: dict[str, Any]) -> dict[str, Any]:
    """Bound certificate identity, validity, hierarchy and policy inputs."""
    try:
        result = certificate_options({"common_name": body.get("common_name", "")})
    except ValueError as error:
        raise CAInputError("Enter a valid common name of at most 64 bytes") from error
    for field, default, maximum in (("days", 3650, 36500), ("path_length", 0, 5)):
        value = body.get(field, default)
        if isinstance(value, bool) or not str(value).isdigit() or len(str(value)) > 5:
            raise CAInputError(f"Invalid {field}")
        result[field] = int(value)
        if not (0 if field == "path_length" else 1) <= result[field] <= maximum:
            raise CAInputError(f"Invalid {field}")
    for field in SUBJECT_FIELDS:
        result[field] = _subject_attribute(field, body.get(field, ""))
    if result["country"] and (
        len(result["country"]) != 2
        or not result["country"].isascii()
        or not result["country"].isalpha()
    ):
        raise CAInputError("Country must contain two letters")
    result["country"] = result["country"].upper()
    if body.get("sans", "") != "":
        try:
            result["sans"] = certificate_options({"sans": body["sans"]})["sans"]
        except ValueError as error:
            raise CAInputError(
                "Invalid SANs; use comma separated DNS names or IP addresses"
            ) from error
    return result


def subject(values: dict[str, Any]) -> x509.Name:
    """Build a subject from fixed attribute names."""
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, values["common_name"]),
            *(
                x509.NameAttribute(oid, values[name])
                for name, oid in SUBJECT_FIELDS.items()
                if values[name]
            ),
        ]
    )


def new_key() -> SigningKey:
    """Generate a root/issuer key locally using the supported default curve."""
    return ec.generate_private_key(ec.SECP384R1())


def key_bytes(key: SigningKey, password: bytes) -> bytes:
    """Serialize private material only with authenticated password protection."""
    return key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)
    )


def load_key(data: bytes, password: bytes) -> SigningKey:
    """Reject unsupported private-key algorithms."""
    key = serialization.load_pem_private_key(data, password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CAInputError("Unsupported CA key")
    return key


def _validity(values: dict[str, Any], parent: x509.Certificate | None) -> tuple[datetime, datetime]:
    """Constrain a child's entire lifetime and delegation depth to its parent."""
    now = datetime.now(UTC).replace(microsecond=0)
    start, end = now - timedelta(minutes=1), now + timedelta(days=values["days"])
    if parent:
        constraints = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca or parent.not_valid_before_utc > now:
            raise CAInputError("Parent is not an active CA")
        if end > parent.not_valid_after_utc:
            raise CAInputError("Child lifetime exceeds parent expiry")
        if constraints.path_length is not None and values["path_length"] >= constraints.path_length:
            raise CAInputError("Parent path-length constraint does not permit this subordinate")
        start = max(start, parent.not_valid_before_utc)
    return start, end


def create_certificate(
    values: dict[str, Any],
    key: SigningKey,
    parent: x509.Certificate | None = None,
    parent_key: SigningKey | None = None,
    public_key: Any = None,
) -> x509.Certificate:
    """Sign a CA with enforced path length and validity bounds."""
    start, end = _validity(values, parent)
    name = subject(values)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(parent.subject if parent else name)
        .public_key(public_key or key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=values["path_length"]), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key or key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((parent_key or key).public_key()),
            False,
        )
    )
    if "sans" in values:
        builder = builder.add_extension(values["sans"], False)
    if values.get("name_constraints"):
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=values["name_constraints"], excluded_subtrees=None
            ),
            True,
        )
    return builder.sign(parent_key or key, hashes.SHA384())
