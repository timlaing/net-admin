"""Durable authority state and serialized, idempotent lifecycle operations."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import secrets
import shutil
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
MANIFEST_FILE = "manifest.json"
DELETIONS_DIRECTORY = "deletions"
JSON_SUFFIX = ".json"
ROOT_RESET_FILE = "root-reset.json"


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


def _remove_authority_directory(directory: Path) -> None:
    """Reclaim stopped issuer directories without granting DAC override capabilities."""
    # Native issuers create private directories under their own UID.
    for parent, directories, _files in os.walk(directory, followlinks=False):
        for name in directories:
            path = Path(parent) / name
            if not path.is_symlink():
                if path.stat().st_uid != os.geteuid():
                    os.chown(path, os.geteuid(), -1)
                path.chmod(0o700)
    shutil.rmtree(directory)


class AuthorityStore:
    """Persist private CA state exclusively inside the runtime container."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in ("authorities", "operations", DELETIONS_DIRECTORY):
            (root / directory).mkdir(exist_ok=True, mode=0o700)
        self.inventory = CertificateInventory(root)
        with self.lock():
            self._finish_reset()
            manifest = root / MANIFEST_FILE
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
            self._recover_authorities()

    def _recover_authorities(self) -> None:
        """Keep individual cleanup failures recoverable without blocking management."""
        for marker in (self.root / DELETIONS_DIRECTORY).glob("*.json"):
            try:
                self._finish_deletion(identifier(marker.stem))
            except OSError:
                logging.getLogger(__name__).warning("CA deletion remains pending: %s", marker.stem)
        try:
            self._clean_incomplete_authorities()
        except OSError:
            logging.getLogger(__name__).warning("Incomplete CA cleanup remains pending")

    def _clean_incomplete_authorities(self) -> None:
        """Remove unpublished children under lock, preserving root and deletion intents."""
        for directory in (self.root / "authorities").iterdir():
            if (
                directory.name == self.manifest["root_id"]
                or directory.is_symlink()
                or not directory.is_dir()
                or (directory / METADATA_FILE).exists()
            ):
                continue
            identifier(directory.name)
            if not self.deletion_pending(directory.name):
                _remove_authority_directory(directory)

    def _deletion_marker(self, authority_id: str) -> Path:
        """Resolve only canonical authority IDs in the controller-owned intent directory."""
        return self.root / DELETIONS_DIRECTORY / (identifier(authority_id) + JSON_SUFFIX)

    def deletion_pending(self, authority_id: str) -> bool:
        """Keep a committed deletion recoverable without authority metadata."""
        return self._deletion_marker(authority_id).is_file()

    def has_children(self, authority_id: str) -> bool:
        """Under the store lock, clean unpublished children and count pending deletions."""
        self._clean_incomplete_authorities()
        paths = [
            *(self.root / "authorities").glob("*/metadata.json"),
            *(self.root / DELETIONS_DIRECTORY).glob("*.json"),
        ]
        return any(json.loads(path.read_text()).get("parent_id") == authority_id for path in paths)

    def _finish_deletion(self, authority_id: str) -> dict[str, Any]:
        """Resume committed non-root deletion and acknowledge its original operation."""
        if authority_id == self.manifest["root_id"]:
            raise CAInputError("Root deletion requires the root reset operation")
        marker = self._deletion_marker(authority_id)
        intent = json.loads(marker.read_text())
        self.inventory.close()
        directory = self.directory(authority_id)
        if directory.exists():
            _remove_authority_directory(directory)
        self.inventory.remove_authority(authority_id)
        result = {"deleted": authority_id}
        self._complete_deletion_operation(intent, authority_id, result)
        marker.unlink()
        return result

    def _complete_deletion_operation(
        self, intent: dict[str, Any], authority_id: str, result: dict[str, Any]
    ) -> None:
        """Preserve the payload digest so recovered requests retain replay protection."""
        record = self.root / "operations" / (identifier(intent["request_id"]) + JSON_SUFFIX)
        if not record.exists():
            return
        previous = json.loads(record.read_text())
        if (
            previous.get("state") == "attempted"
            and previous.get("action") == "delete"
            and previous.get("authority_id") == authority_id
        ):
            durable(
                record, json.dumps({**previous, "state": "complete", "result": result}).encode()
            )

    def _finish_reset(self) -> None:
        """Finish an explicitly requested root replacement after interruption."""
        marker = self.root / ROOT_RESET_FILE
        if not marker.exists():
            return
        reset = json.loads(marker.read_text())
        self.inventory.remove_authority(identifier(reset["old_id"]))
        directory = self.directory(reset["old_id"])
        if directory.exists():
            shutil.rmtree(directory)
        durable(self.root / ROOT_PRIVATE_FILE, reset["key"].encode())
        durable(self.root / ROOT_WRAP_FILE, reset["password"].encode())
        durable(self.root / MANIFEST_FILE, json.dumps(reset["manifest"]).encode())
        if "request_id" in reset:
            self._complete_deletion_operation(reset, reset["old_id"], {"deleted": reset["old_id"]})
        self.manifest = reset["manifest"]
        marker.unlink()

    def delete_authority(self, body: dict[str, Any]) -> dict[str, Any]:
        """Remove a childless authority and rotate the root on explicit reset."""
        authority_id = identifier(str(body.get("authority_id", "")))
        if body.get("confirmation") != "DELETE CA":
            raise CAInputError("Type DELETE CA to confirm")
        if self.deletion_pending(authority_id):
            return self._finish_deletion(authority_id)
        directory = self.directory(authority_id)
        if not (directory / METADATA_FILE).exists():
            raise CAInputError("Unknown authority")
        if self.has_children(authority_id):
            raise CAInputError("Delete child authorities first")
        if authority_id == self.manifest["root_id"]:
            password = secrets.token_urlsafe(48)
            key = new_key()
            public = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            manifest = {
                "version": 1,
                "root_id": uuid.uuid4().hex,
                "public_key_sha256": hashlib.sha256(public).hexdigest(),
            }
            durable(
                self.root / ROOT_RESET_FILE,
                json.dumps(
                    {
                        "old_id": authority_id,
                        "request_id": identifier(str(body.get("request_id", ""))),
                        "manifest": manifest,
                        "key": key_bytes(key, password.encode()).decode(),
                        "password": password,
                    }
                ).encode(),
            )
            self._finish_reset()
            self.manifest = manifest
        else:
            intent = {
                "request_id": identifier(str(body.get("request_id", ""))),
                "parent_id": self.metadata(authority_id)["parent_id"],
            }
            durable(self._deletion_marker(authority_id), json.dumps(intent).encode())
            return self._finish_deletion(authority_id)
        return {"deleted": authority_id}

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
        record = self.root / "operations" / (operation_id + JSON_SUFFIX)
        with self.lock():
            if record.exists():
                return self._existing_operation(record, body, digest)
            durable(
                record,
                json.dumps(
                    {
                        "digest": digest,
                        "state": "attempted",
                        "authority_id": body.get("authority_id")
                        if body.get("action") == "delete"
                        else body.get("issuer_id"),
                        "action": body.get("action"),
                    }
                ).encode(),
            )
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

    def _existing_operation(
        self, record: Path, body: dict[str, Any], digest: str
    ) -> dict[str, Any]:
        """Allow only a matching committed deletion to resume an attempted request."""
        previous = json.loads(record.read_text())
        if previous["digest"] != digest:
            raise CAInputError("Request ID already used with different inputs")
        if previous["state"] == "rejected":
            raise CAInputError(previous["error"])
        if previous["state"] == "complete":
            return cast(dict[str, Any], previous["result"])
        if previous["state"] == "attempted" and body.get("action") == "delete":
            authority_id = identifier(str(body.get("authority_id", "")))
            if self.deletion_pending(authority_id):
                return self._finish_deletion(authority_id)
            marker = self.root / ROOT_RESET_FILE
            if marker.exists():
                reset = json.loads(marker.read_text())
                if (
                    reset.get("request_id") == body["request_id"]
                    and reset["old_id"] == authority_id
                ):
                    self._finish_reset()
                    return {"deleted": authority_id}
        raise CAInputError("Operation needs reconciliation; inspect authority state before retry")

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
        durable(self.root / MANIFEST_FILE, json.dumps(self.manifest).encode())
        (self.root / ROOT_PRIVATE_FILE).unlink(missing_ok=True)
        (self.root / ROOT_WRAP_FILE).unlink(missing_ok=True)
        return {"archived": True}
