"""Pure validation for subnet editing; privileged changes remain with the agent."""

from ipaddress import IPv4Address, IPv4Network
from typing import Any


def _pool_addresses(line: str, subnet: IPv4Network) -> tuple[IPv4Address, IPv4Address]:
    parts = [part.strip() for part in line.split("-")]
    if len(parts) != 2:
        raise ValueError("Enter each pool as start-end, one per line.")
    start, end = (IPv4Address(part) for part in parts)
    if start > end or start not in subnet or end not in subnet:
        raise ValueError("Pools must be ordered and contained in this subnet.")
    if start == subnet.network_address or end == subnet.broadcast_address:
        raise ValueError("Pools cannot include the network or broadcast address.")
    return start, end


def _subnet_options(options: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in options.splitlines():
        if not line.strip():
            continue
        name, separator, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or not value:
            raise ValueError("Enter each option as name=value, one per line.")
        if name in parsed:
            raise ValueError(f"Duplicate option: {name}.")
        parsed[name] = value
    return parsed


def subnet_payload(network: str, netmask: str, pools: str, options: str) -> dict[str, Any]:
    """Reject malformed or overlapping pools and ambiguous option input."""
    subnet = IPv4Network(f"{network}/{netmask}")
    ranges: list[list[str]] = []
    intervals: list[tuple[int, int]] = []
    for line in pools.splitlines():
        if not line.strip():
            continue
        start, end = _pool_addresses(line, subnet)
        if any(int(start) <= last and int(end) >= first for first, last in intervals):
            raise ValueError("Allocation pools must not overlap.")
        intervals.append((int(start), int(end)))
        ranges.append([str(start), str(end)])
    return {"network": network, "ranges": ranges, "options": _subnet_options(options)}
