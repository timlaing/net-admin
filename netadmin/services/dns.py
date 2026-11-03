"""Bind AXFR and RFC 2136 adapter."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

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


class BindService:  # pylint: disable=too-many-instance-attributes
    """Read and mutate authoritative Bind zones."""

    def __init__(
        self,
        server: str,
        key_name: str,
        key_secret: str,
        algorithm: str = "hmac-sha256",
        config_path: Path | None = None,
        configured_zones: tuple[str, ...] = (),
        port: int = 53,
    ) -> None:
        self.zone_agent: AgentClient | None = None
        self.server = server
        self.port = port
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
            port=self.port,
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
        response = dns.query.tcp(update, self.server, port=self.port, timeout=10)
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
        response = dns.query.tcp(update, self.server, port=self.port, timeout=10)
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
        previous = [
            item
            for item in self.records(forward_zone)
            if item.record_type == "A" and item.name.rstrip(".") == forward_name
        ]
        self.upsert(forward_zone, forward_name, "A", ttl, str(parsed))
        try:
            self.upsert(reverse_zone, pointer_name, "PTR", ttl, fqdn)
        except Exception:
            if previous:
                self.restore_addresses(forward_zone, forward_name, previous)
            else:
                self.delete(forward_zone, forward_name, "A", str(parsed))
            raise

    def restore_addresses(self, zone: str, name: str, previous: list[DnsRecord]) -> None:
        """Restore the full original A RRset in one authenticated update."""
        update = dns.update.Update(
            zone,
            keyring=self.keyring,
            keyname=dns.name.from_text(self.key_name),
            keyalgorithm=self.algorithm,
        )
        update.replace(name, previous[0].ttl, "A", *(item.value for item in previous))
        response = dns.query.tcp(update, self.server, port=self.port, timeout=10)
        if response.rcode() != 0:
            raise RuntimeError(f"DNS rollback failed with rcode {response.rcode()}")


class AgentDnsService(BindService):
    """Keep zone and record operations behind the authenticated DNS agent."""

    def __init__(self, client: AgentClient) -> None:
        super().__init__("", "", "")
        self.zone_agent = client
        self.client = client

    def records(self, zone_name: str) -> list[DnsRecord]:
        """Read records without exposing Bind transport credentials to the app."""
        return [
            DnsRecord(**item)
            for item in self.client.get("records?" + urlencode({"zone": zone_name}))
        ]

    def snapshot_records(self, zone_name: str) -> list[DnsRecord]:
        """Read the persisted zone file and journal, which may lag in-memory state."""
        return [
            DnsRecord(**item)
            for item in self.client.get(
                "records?" + urlencode({"zone": zone_name, "source": "file"})
            )
        ]

    def upsert(self, zone: str, name: str, record_type: str, ttl: int, value: str) -> None:
        """Replace one RRset through the agent."""
        self.client.post(
            "records",
            {"zone": zone, "name": name, "record_type": record_type, "ttl": ttl, "value": value},
        )

    def delete(self, zone: str, name: str, record_type: str, value: str = "") -> None:
        """Remove a record through the agent."""
        self.client.post(
            "records/delete",
            {"zone": zone, "name": name, "record_type": record_type, "value": value},
        )

    def restore_addresses(self, zone: str, name: str, previous: list[DnsRecord]) -> None:
        """Restore an A RRset through the authenticated agent, never directly."""
        self.client.post(
            "records",
            {
                "zone": zone,
                "name": name,
                "record_type": "A",
                "ttl": previous[0].ttl,
                "values": [item.value for item in previous],
            },
        )
