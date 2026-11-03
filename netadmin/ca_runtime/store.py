"""Durable authority state and serialized, idempotent lifecycle operations."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import tempfile
import uuid
from collections.abc import Callable, Iterator
from ipaddress import ip_network
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from netadmin.ca_runtime.certificates import (
    PEM,
    CAInputError,
    create_certificate,
    key_bytes,
    load_key,
    new_key,
    options,
)
from netadmin.ca_runtime.inventory import CertificateInventory
from netadmin.services.radius_certificates import SigningKey, certificate_info

ROOT_WRAP_FILE = "root.password"
ROOT_PRIVATE_FILE = "root.key"
AUTHORITY_CERT_FILE = "ca.crt"
AUTHORITY_KEY_FILE = "ca.key"
AUTHORITY_WRAP_FILE = "password"
METADATA_FILE = "metadata.json"


def durable(path: Path, data: bytes) -> None:
    """Publish a restricted file only after flushing its complete contents."""
    descriptor, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(name).unlink(missing_ok=True)


def identifier(value: str) -> str:
    """Accept only canonical UUID hex path components."""
    if len(value) != 32 or uuid.UUID(hex=value).hex != value:
        raise CAInputError("Invalid authority or operation ID")
    return value


class AuthorityStore:
    """Persist private CA state exclusively inside the runtime container."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in ("authorities", "operations"):
            (root / directory).mkdir(exist_ok=True, mode=0o700)
        with self.lock():
            manifest = root / "manifest.json"
            if not manifest.exists():
                if (root / "config/ca.json").exists() or (root / "certs/root_ca.crt").exists():
                    raise CAInputError(
                        "Existing step-ca state requires explicit migration; no root generated"
                    )
                # Interrupted first boot must be inspected, never silently re-keyed.
                if (root / ROOT_PRIVATE_FILE).exists() or (root / ROOT_WRAP_FILE).exists():
                    raise CAInputError("Incomplete initial root state; recovery required")
                password = secrets.token_urlsafe(48).encode()
                durable(root / ROOT_WRAP_FILE, password)
                key = new_key()
                durable(root / ROOT_PRIVATE_FILE, key_bytes(key, password))
                public = key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                durable(
                    manifest,
                    json.dumps(
                        {
                            "version": 1,
                            "root_id": uuid.uuid4().hex,
                            "public_key_sha256": hashlib.sha256(public).hexdigest(),
                        }
                    ).encode(),
                )
            self.manifest = json.loads(manifest.read_text())
            if self.manifest.get("version") != 1:
                raise CAInputError("Unsupported CA state version")
            if self.manifest.get("root_archived"):
                (root / ROOT_PRIVATE_FILE).unlink(missing_ok=True)
                (root / ROOT_WRAP_FILE).unlink(missing_ok=True)
            elif not (root / ROOT_PRIVATE_FILE).exists() or not (root / ROOT_WRAP_FILE).exists():
                raise CAInputError("Missing root material; recovery required")
            if not self.manifest.get("root_archived"):
                self._verify_root()
        self.inventory = CertificateInventory(root)

    def _verify_root(self) -> None:
        """Check both the recorded key identity and any initialized root certificate."""
        key = self.key(self.manifest["root_id"], {})
        public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if hashlib.sha256(public).hexdigest() != self.manifest["public_key_sha256"]:
            raise CAInputError("Root key does not match manifest fingerprint")
        root_certificate = self.directory(self.manifest["root_id"]) / AUTHORITY_CERT_FILE
        if root_certificate.exists():
            certificate_public = (
                self.certificate(self.manifest["root_id"])
                .public_key()
                .public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            if certificate_public != public:
                raise CAInputError("Root certificate does not match root key")

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """Serialize initialization, signing and publication across processes."""
        with (self.root / "lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def directory(self, authority_id: str) -> Path:
        """Resolve an authority without interpreting caller-controlled paths."""
        return self.root / "authorities" / identifier(authority_id)

    def certificate(self, authority_id: str) -> x509.Certificate:
        """Load an existing public authority certificate."""
        return x509.load_pem_x509_certificate(
            (self.directory(authority_id) / AUTHORITY_CERT_FILE).read_bytes()
        )

    def key(self, authority_id: str, recovery: dict[str, Any]) -> SigningKey:
        """Use a local key, or decrypt uploaded archived root material in memory."""
        if authority_id == self.manifest["root_id"]:
            if (self.root / ROOT_PRIVATE_FILE).exists():
                return load_key(
                    (self.root / ROOT_PRIVATE_FILE).read_bytes(),
                    (self.root / ROOT_WRAP_FILE).read_bytes(),
                )
            key = load_key(
                str(recovery.get("recovery_key", "")).encode(),
                str(recovery.get("recovery_password", "")).encode(),
            )
            if key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != self.certificate(authority_id).public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                raise CAInputError("Recovery key does not match this root")
            return key
        directory = self.directory(authority_id)
        return load_key(
            (directory / AUTHORITY_KEY_FILE).read_bytes(),
            (directory / AUTHORITY_WRAP_FILE).read_bytes(),
        )

    def metadata(self, authority_id: str) -> dict[str, Any]:
        """Read public identity and issuer configuration metadata."""
        return cast(
            dict[str, Any], json.loads((self.directory(authority_id) / METADATA_FILE).read_text())
        )

    def status(self) -> dict[str, Any]:
        """Return only public state; secret files never become API metadata."""
        authorities = []
        for path in sorted((self.root / "authorities").glob("*/metadata.json")):
            metadata = json.loads(path.read_text())
            certificate = self.certificate(path.parent.name)
            authorities.append(
                {
                    **metadata,
                    **certificate_info(certificate),
                    "id": path.parent.name,
                    "pem": certificate.public_bytes(PEM).decode(),
                }
            )
        names = {item["id"]: item["common_name"] for item in authorities}
        for item in authorities:
            item["parent_name"] = names.get(item["parent_id"], "Self-signed root")
        return {
            **self.manifest,
            "state": "ready" if authorities else "key_ready",
            "root_online": (self.root / ROOT_PRIVATE_FILE).exists(),
            "authorities": authorities,
        }

    def operation(
        self, body: dict[str, Any], action: Callable[[], dict[str, Any]]
    ) -> dict[str, Any]:
        """Reject changed retries and retain ambiguous operations for reconciliation."""
        operation_id = identifier(str(body.get("request_id", "")))
        public_payload = {
            name: value
            for name, value in body.items()
            if name not in {"password", "recovery_password", "recovery_key"}
        }
        digest = hashlib.sha256(json.dumps(public_payload, sort_keys=True).encode()).hexdigest()
        record = self.root / "operations" / (operation_id + ".json")
        with self.lock():
            if record.exists():
                previous = json.loads(record.read_text())
                if previous["digest"] != digest:
                    raise CAInputError("Request ID already used with different inputs")
                if previous["state"] == "rejected":
                    raise CAInputError(previous["error"])
                if previous["state"] != "complete":
                    raise CAInputError(
                        "Operation needs reconciliation; inspect authority state before retry"
                    )
                return cast(dict[str, Any], previous["result"])
            durable(record, json.dumps({"digest": digest, "state": "attempted"}).encode())
            try:
                result = action()
            except CAInputError as error:
                durable(
                    record,
                    json.dumps(
                        {"digest": digest, "state": "rejected", "error": str(error)}
                    ).encode(),
                )
                raise
            durable(
                record,
                json.dumps({"digest": digest, "state": "complete", "result": result}).encode(),
            )
            return result

    def create_root(self, body: dict[str, Any]) -> dict[str, Any]:
        """Self-sign the first-boot root key, without replacing an existing root."""
        root_id = self.manifest["root_id"]
        directory = self.directory(root_id)
        if directory.exists():
            raise CAInputError("Root already initialized; use its public certificate")
        values = options(body)
        key = self.key(root_id, {})
        certificate = create_certificate(values, key)
        directory.mkdir(mode=0o700)
        durable(directory / AUTHORITY_CERT_FILE, certificate.public_bytes(PEM))
        durable(
            directory / METADATA_FILE,
            json.dumps(
                {
                    "parent_id": None,
                    "managed": False,
                    "common_name": values["common_name"],
                    "path_length": values["path_length"],
                }
            ).encode(),
        )
        return {"id": root_id}

    def create_subordinate(self, body: dict[str, Any]) -> dict[str, Any]:
        """Sign a fixed CA template using a managed or externally held child key."""
        parent_id = identifier(str(body.get("parent_id", "")))
        parent = self.certificate(parent_id)
        if parent_id != self.manifest["root_id"] and not all(
            (self.directory(parent_id) / name).is_file()
            for name in (AUTHORITY_KEY_FILE, AUTHORITY_WRAP_FILE)
        ):
            raise CAInputError("Parent signing material is unavailable or externally held")
        values = options(body)
        key = new_key()
        csr_pem = body.get("csr", "")
        public_key = None
        if csr_pem:
            csr = x509.load_pem_x509_csr(str(csr_pem).encode())
            if not csr.is_signature_valid:
                raise CAInputError("Invalid CSR signature")
            public_key = csr.public_key()
            from cryptography.hazmat.primitives.asymmetric import ec, rsa  # pylint: disable=import-outside-toplevel

            if not isinstance(
                public_key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey
            ) or public_key.key_size < (
                256 if isinstance(public_key, ec.EllipticCurvePublicKey) else 2048
            ):
                raise CAInputError("Unsupported CSR key")
        limits = body.get("effective_policy")
        if csr_pem and limits:
            values["name_constraints"] = [
                *(x509.DNSName(name) for name in limits["dns"] if not name.startswith("*.")),
                *(x509.IPAddress(ip_network(value)) for value in limits["ips"]),
            ]
        certificate = create_certificate(values, key, parent, self.key(parent_id, body), public_key)
        authority_id = uuid.uuid4().hex
        directory = self.directory(authority_id)
        directory.mkdir(mode=0o700)
        durable(directory / AUTHORITY_CERT_FILE, certificate.public_bytes(PEM))
        durable(directory / "chain.pem", certificate.public_bytes(PEM) + self.chain(parent_id))
        if not csr_pem:
            password = secrets.token_urlsafe(48).encode()
            durable(directory / AUTHORITY_WRAP_FILE, password)
            durable(directory / AUTHORITY_KEY_FILE, key_bytes(key, password))
        metadata = {
            "parent_id": parent_id,
            "managed": not bool(csr_pem),
            "policy": body.get("effective_policy"),
            "common_name": values["common_name"],
            "path_length": values["path_length"],
        }
        durable(directory / METADATA_FILE, json.dumps(metadata).encode())
        return {"id": authority_id}

    def chain(self, authority_id: str) -> bytes:
        """Return the public chain through the root."""
        directory = self.directory(authority_id)
        path = directory / "chain.pem"
        return (
            path.read_bytes() if path.exists() else (directory / AUTHORITY_CERT_FILE).read_bytes()
        )

    def export_root(self, body: dict[str, Any]) -> dict[str, Any]:
        """Re-encrypt root recovery material with an independent operator passphrase."""
        password = str(body.get("password", ""))
        if not 16 <= len(password) <= 1024:
            raise CAInputError("Recovery passphrase must contain 16 to 1024 characters")
        root_id = self.manifest["root_id"]
        key = self.key(root_id, {})
        return {
            "key": key_bytes(key, password.encode()).decode(),
            "certificate": self.chain(root_id).decode(),
            "root_id": root_id,
        }

    def archive_root(self, body: dict[str, Any]) -> dict[str, Any]:
        """Verify the saved encrypted recovery copy before removing the online key."""
        if body.get("confirmation") != "ARCHIVE ROOT":
            raise CAInputError("Type ARCHIVE ROOT to confirm")
        key = load_key(
            str(body.get("recovery_key", "")).encode(),
            str(body.get("recovery_password", "")).encode(),
        )
        if key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != self.certificate(self.manifest["root_id"]).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise CAInputError("Recovery key does not match the root")
        self.manifest["root_archived"] = True
        durable(self.root / "manifest.json", json.dumps(self.manifest).encode())
        (self.root / ROOT_PRIVATE_FILE).unlink(missing_ok=True)
        (self.root / ROOT_WRAP_FILE).unlink(missing_ok=True)
        return {"archived": True}
