"""Smallstep issuing services supervised within the CA runtime container."""

from __future__ import annotations

import json
import os
import secrets
import subprocess  # nosec B404
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.store import AuthorityStore, durable
from netadmin.services.radius_certificates import certificate_options

PROVISIONER_CREDENTIAL_FILE = "provisioner.password"
ROOT_TRUST_FILE = "root.crt"


def run(arguments: list[str]) -> str:
    """Execute bounded fixed CLI commands; never log their potentially secret output."""
    result = subprocess.run(  # noqa: S603
        ["/usr/local/bin/step", *arguments],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    return result.stdout.strip()


def policy(body: dict[str, Any]) -> dict[str, Any]:
    """Require explicit DNS or IP scope for a managed issuer."""
    dns_text = str(body.get("dns_suffixes", ""))
    dns_names = []
    if dns_text:
        names = certificate_options({"sans": dns_text})["sans"]
        for name in names:
            if not isinstance(name, x509.DNSName) or name.value.startswith("*."):
                raise CAInputError("Use DNS suffixes without wildcard prefixes")
            dns_names.extend([name.value, "*." + name.value])
    ip_text = str(body.get("ip_ranges", ""))
    if len(ip_text) > 4096:
        raise CAInputError("Too many IP ranges")
    networks = [str(ip_network(value.strip())) for value in ip_text.split(",") if value.strip()]
    if not dns_names and not networks:
        raise CAInputError("Specify permitted DNS suffixes or IP ranges")
    days = body.get("leaf_days", "365")
    certificate_options({"days": days})
    return {"dns": dns_names, "ips": networks, "leaf_days": int(days)}


def service_host(body: dict[str, Any]) -> str:
    """Validate endpoints before publishing a subordinate certificate."""
    host = str(body.get("service_host", ""))
    if not host or ":" in host or "/" in host or host.startswith("*."):
        raise CAInputError("Enter a DNS service hostname or IPv4 address without a port")
    names = certificate_options({"sans": host})["sans"]
    if len(names) != 1:
        raise CAInputError("Specify exactly one service hostname or IPv4 address")
    return str(names[0].value)


def dns_rule_subset(child: str, parent: str) -> bool:
    """Smallstep wildcards match exactly one label, not arbitrary subtree depth."""
    if child == parent:
        return True
    return (
        not child.startswith("*.")
        and parent.startswith("*.")
        and len(child.split(".")) == len(parent.split("."))
        and child.endswith(parent[1:])
    )


def check_parent_policy(store: AuthorityStore, parent_id: str, child: dict[str, Any]) -> None:
    """A delegated runtime policy may narrow, but never expand its ancestors."""
    parent = store.metadata(parent_id)
    limits = parent.get("policy")
    if limits:
        for name in child["dns"]:
            if not any(dns_rule_subset(name, rule) for rule in limits["dns"]):
                raise CAInputError("Child DNS policy exceeds parent policy")
        for network in child["ips"]:
            child_net = ip_network(network)
            if not any(
                child_net.version == ip_network(value).version
                and int(child_net.network_address) >= int(ip_network(value).network_address)
                and int(child_net.broadcast_address) <= int(ip_network(value).broadcast_address)
                for value in limits["ips"]
            ):
                raise CAInputError("Child IP policy exceeds parent policy")
        if child["leaf_days"] > limits["leaf_days"]:
            raise CAInputError("Child leaf lifetime policy exceeds parent policy")
    if parent.get("parent_id"):
        check_parent_policy(store, parent["parent_id"], child)


def configure(store: AuthorityStore, authority_id: str, body: dict[str, Any]) -> None:
    """Create an isolated issuer database, credentials and explicit leaf template."""
    limits = policy(body)
    directory = store.directory(authority_id)
    metadata = store.metadata(authority_id)
    host = service_host(body)
    configured = list((store.root / "authorities").glob("*/config.json"))
    port = 9100 + len(configured)
    password_path = directory / PROVISIONER_CREDENTIAL_FILE
    durable(password_path, secrets.token_urlsafe(48).encode())
    run(
        [
            "crypto",
            "jwk",
            "create",
            str(directory / "jwk.pub"),
            str(directory / "jwk.enc"),
            "--kty",
            "EC",
            "--crv",
            "P-256",
            "--password-file",
            str(password_path),
        ]
    )
    root_cert = store.chain(authority_id)
    durable(
        directory / ROOT_TRUST_FILE,
        x509.load_pem_x509_certificates(root_cert)[-1].public_bytes(Encoding.PEM),
    )
    chain = x509.load_pem_x509_certificates(root_cert)
    # step-ca's crt is the issuing certificate followed by non-root intermediates.
    durable(
        directory / "issuing-chain.pem",
        b"".join(cert.public_bytes(Encoding.PEM) for cert in chain[:-1]),
    )
    template = {
        "subject": "SUBJECT",
        "sans": "SANS",
        "keyUsage": ["digitalSignature"],
        "extKeyUsage": ["serverAuth", "clientAuth"],
        "basicConstraints": {"isCA": False},
        "crlDistributionPoints": [f"https://{host}:{port}/1.0/crl"],
    }
    config: dict[str, Any] = {
        "root": str(directory / ROOT_TRUST_FILE),
        "crt": str(directory / "issuing-chain.pem"),
        "key": str(directory / "ca.key"),
        "address": f":{port}",
        "dnsNames": ["localhost", "ca-runtime", host],
        "db": {"type": "badgerv2", "dataSource": str(directory / "db")},
        "crl": {"enabled": True, "generateOnRevoke": True},
        "authority": {
            "provisioners": [
                {
                    "type": "JWK",
                    "name": "netadmin",
                    "key": json.loads((directory / "jwk.pub").read_text()),
                    "encryptedKey": (directory / "jwk.enc").read_text().strip(),
                    "claims": {
                        "minTLSCertDuration": "5m",
                        "defaultTLSCertDuration": "24h",
                        "maxTLSCertDuration": f"{limits['leaf_days'] * 24}h",
                    },
                    "policy": {
                        "x509": {
                            "allow": {"dns": limits["dns"], "ip": limits["ips"]},
                            "allowWildcardNames": False,
                        }
                    },
                    "options": {
                        "x509": {
                            "template": json.dumps(template)
                            .replace('"SUBJECT"', "{{ toJson .Subject }}")
                            .replace('"SANS"', "{{ toJson .SANs }}")
                        }
                    },
                }
            ]
        },
    }
    # Open-source step-ca supports authority-level policies, not per-JWK policies.
    config["authority"]["policy"] = config["authority"]["provisioners"][0].pop("policy")
    durable(directory / "config.json", json.dumps(config).encode())
    durable(
        directory / "metadata.json",
        json.dumps(
            {**metadata, "port": port, "endpoint": f"https://{host}:{port}", "policy": limits}
        ).encode(),
    )


class Issuers:
    """Own child process lifecycle without Docker or host process access."""

    def __init__(self, store: AuthorityStore):
        self.store = store
        self.processes: dict[str, subprocess.Popen[bytes]] = {}

    def reconcile(self) -> None:
        """Start eligible issuers and stop expired signing services."""
        for path in (self.store.root / "authorities").glob("*/config.json"):
            authority_id = path.parent.name
            process = self.processes.get(authority_id)
            cert = self.store.certificate(authority_id)
            if cert.not_valid_after_utc <= datetime.now(UTC):
                if process and process.poll() is None:
                    process.terminate()
                continue
            if process and process.poll() is None:
                continue
            # Logs remain in the CA's restricted volume, never returned to the UI.
            with (path.parent / "service.log").open("ab") as log:
                self.processes[authority_id] = subprocess.Popen(  # noqa: S603 # pylint: disable=consider-using-with
                    [
                        "/usr/local/bin/step-ca",
                        str(path),
                        "--password-file",
                        str(path.parent / "password"),
                    ],
                    stdout=log,
                    stderr=log,
                    stdin=subprocess.DEVNULL,
                    env={**os.environ, "HOME": str(self.store.root)},
                )

    def close(self) -> None:
        """Reap every child when the controller shuts down."""
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def sign(store: AuthorityStore, authority_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Issue a leaf with a scoped provisioner, preserving replay identity."""
    from netadmin.services.step_ca import issued_matches_csr, validate_csr  # pylint: disable=import-outside-toplevel

    directory = store.directory(authority_id)
    metadata = store.metadata(authority_id)
    csr = validate_csr(str(body.get("csr", "")))
    days = certificate_options({"days": body.get("days", "365")})["days"]
    if (
        datetime.now(UTC) + timedelta(days=days)
        > store.certificate(authority_id).not_valid_after_utc
    ):
        raise CAInputError("Requested leaf lifetime exceeds issuing CA expiry")
    operation_id = str(body["request_id"])
    request = directory / (operation_id + ".csr")
    output = directory / (operation_id + ".pem")
    durable(request, str(body["csr"]).encode())
    run(
        [
            "ca",
            "sign",
            str(request),
            str(output),
            "--not-after",
            f"{days * 24}h",
            "--ca-url",
            f"https://localhost:{metadata['port']}",
            "--root",
            str(directory / ROOT_TRUST_FILE),
            "--provisioner",
            "netadmin",
            "--provisioner-password-file",
            str(directory / PROVISIONER_CREDENTIAL_FILE),
        ]
    )
    certificate = issued_matches_csr(output.read_bytes(), csr)
    certificate.verify_directly_issued_by(store.certificate(authority_id))
    return {"pem": output.read_text(), "issuer_id": authority_id}


def revocation(store: AuthorityStore, authority_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Revoke an issuer-specific leaf serial with scoped Smallstep credentials."""
    serial = str(body.get("serial", ""))
    if not 1 <= len(serial) <= 40 or any(char not in "0123456789abcdefABCDEF" for char in serial):
        raise CAInputError("Enter a hexadecimal certificate serial")
    number = int(serial, 16)
    if not number or str(body.get("reason", "0")) not in {"0", "1", "3", "4", "5", "9"}:
        raise CAInputError("Invalid revocation serial or reason")
    directory = store.directory(authority_id)
    metadata = store.metadata(authority_id)
    flags = [
        "--ca-url",
        f"https://localhost:{metadata['port']}",
        "--root",
        str(directory / ROOT_TRUST_FILE),
    ]
    if revoked(store, authority_id, number):
        return {"revoked": True}
    token = run(
        [
            "ca",
            "token",
            str(number),
            "--revoke",
            *flags,
            "--provisioner",
            "netadmin",
            "--provisioner-password-file",
            str(directory / PROVISIONER_CREDENTIAL_FILE),
        ]
    )
    run(
        [
            "ca",
            "revoke",
            str(number),
            "--token",
            token,
            "--reasonCode",
            str(body.get("reason", "0")),
            *flags,
        ]
    )
    if not revoked(store, authority_id, number):
        raise OSError("Revocation outcome requires CRL reconciliation")
    return {"revoked": True}


def crl(store: AuthorityStore, authority_id: str) -> x509.CertificateRevocationList:
    """Fetch the native issuer CRL using pinned root trust."""
    import ssl  # pylint: disable=import-outside-toplevel

    import httpx  # pylint: disable=import-outside-toplevel

    directory = store.directory(authority_id)
    metadata = store.metadata(authority_id)
    context = ssl.create_default_context(cafile=str(directory / ROOT_TRUST_FILE))
    with httpx.Client(verify=context, trust_env=False) as client:
        response = client.get(f"https://localhost:{metadata['port']}/1.0/crl", timeout=10)
        response.raise_for_status()
    return x509.load_der_x509_crl(response.content)


def revoked(store: AuthorityStore, authority_id: str, serial: int) -> bool:
    """Consult the authoritative signed CRL, including on retried revocations."""
    return crl(store, authority_id).get_revoked_certificate_by_serial_number(serial) is not None
