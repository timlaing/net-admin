"""Bind AXFR and RFC 2136 adapter."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

import dns.name
import dns.query
import dns.tsigkeyring
import dns.update
import dns.zone

from netadmin.services.agents import AgentClient


@dataclass(frozen=True, slots=True)
class DnsRecord:
    """Rendered DNS record."""

    name: str
    ttl: int
    record_type: str
    value: str


@dataclass(frozen=True, slots=True)
class DnsZone:
    """Configured authoritative zone."""

    name: str
    file: str
    dynamic: bool


def discover_zones(text: str) -> list[DnsZone]:
    """Discover authoritative zones from named.conf declarations."""
    result = []
    for match in re.finditer(r'(?ms)zone\s+"([^"]+)"[^\{]*\{(.*?)\};', text):
        name, body = match.groups()
        if not re.search(r"\btype\s+(master|primary)\s*;", body):
            continue
        filename = re.search(r'\bfile\s+"([^"]+)"\s*;', body)
        result.append(
            DnsZone(name.rstrip("."), filename.group(1) if filename else "", "allow-update" in body)
        )
    return result


class BindService:
    """Read and mutate authoritative Bind zones."""

    def __init__(
        self,
        server: str,
        key_name: str,
        key_secret: str,
        algorithm: str = "hmac-sha256",
        config_path: Path | None = None,
        configured_zones: tuple[str, ...] = (),
    ) -> None:
        self.zone_agent: AgentClient | None = None
        self.server = server
        self.key_name = key_name
        self.keyring = dns.tsigkeyring.from_text({key_name: key_secret}) if key_secret else None
        self.algorithm = algorithm
        self.config_path = config_path
        self.configured_zones = configured_zones

    def zones(self) -> list[DnsZone]:
        """Return zones declared by the mounted Bind configuration."""
        if self.zone_agent is not None:
            return [
                DnsZone(str(item["name"]), str(item["file"]), bool(item["dynamic"]))
                for item in self.zone_agent.get("zones")
            ]
        if self.config_path is None:
            return [DnsZone(name, "", True) for name in self.configured_zones]
        return discover_zones(self.config_path.read_text(encoding="utf-8"))

    def records(self, zone_name: str) -> list[DnsRecord]:
        """Read current zone state with AXFR."""
        transfer = dns.query.xfr(
            self.server,
            zone_name,
            keyring=self.keyring,
            keyname=self.key_name if self.keyring else None,
            relativize=True,
            lifetime=10,
        )
        zone = dns.zone.from_xfr(transfer)
        records: list[DnsRecord] = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for record in rdataset:
                    records.append(
                        DnsRecord(
                            name.to_text(), rdataset.ttl, rdataset.rdtype.name, record.to_text()
                        )
                    )
        return sorted(records, key=lambda item: (item.name, item.record_type, item.value))

    def upsert(self, zone: str, name: str, record_type: str, ttl: int, value: str) -> None:
        """Replace an RRset using authenticated dynamic update."""
        update = dns.update.Update(
            zone,
            keyring=self.keyring,
            keyname=dns.name.from_text(self.key_name),
            keyalgorithm=self.algorithm,
        )
        update.replace(name, ttl, record_type, value)
        response = dns.query.tcp(update, self.server, timeout=10)
        if response.rcode() != 0:
            raise RuntimeError(f"DNS update failed with rcode {response.rcode()}")

    def delete(self, zone: str, name: str, record_type: str, value: str = "") -> None:
        """Delete one value or a complete RRset."""
        update = dns.update.Update(
            zone,
            keyring=self.keyring,
            keyname=dns.name.from_text(self.key_name),
            keyalgorithm=self.algorithm,
        )
        if value:
            update.delete(name, record_type, value)
        else:
            update.delete(name, record_type)
        response = dns.query.tcp(update, self.server, timeout=10)
        if response.rcode() != 0:
            raise RuntimeError(f"DNS delete failed with rcode {response.rcode()}")

    def add_host(
        self, hostname: str, address: str, forward_zone: str, reverse_zone: str, ttl: int
    ) -> None:
        """Create paired A/PTR records, compensating if the PTR update fails."""
        parsed = ipaddress.IPv4Address(address)
        forward_name = hostname.rstrip(".")
        fqdn = f"{forward_name}.{forward_zone.rstrip('.')}."
        reverse_suffix = reverse_zone.rstrip(".")
        full_pointer = parsed.reverse_pointer
        pointer_name = full_pointer.removesuffix(f".{reverse_suffix}").rstrip(".")
        self.upsert(forward_zone, forward_name, "A", ttl, str(parsed))
        try:
            self.upsert(reverse_zone, pointer_name, "PTR", ttl, fqdn)
        except Exception:
            self.delete(forward_zone, forward_name, "A", str(parsed))
            raise
