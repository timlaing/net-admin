"""ISC DHCPD include discovery and loss-minimizing transforms."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

INCLUDE = re.compile(r'\binclude\s+"([^"]+)"\s*;', re.IGNORECASE)
HOST_START = re.compile(r"\bhost\s+([A-Za-z0-9_-]+)\s*\{")
SUBNET_START = re.compile(r"\bsubnet\s+([0-9.]+)\s+netmask\s+([0-9.]+)\s*\{", re.IGNORECASE)
_SHARED_NETWORK_START = re.compile(r"\bshared-network\s+[A-Z0-9_-]+\s*\{", re.IGNORECASE)
_POOL_START = re.compile(r"\bpool\s*\{", re.IGNORECASE)
_COMMENTS_AND_STRINGS = re.compile(r'#[^\n]*|"(?:\\.|[^"\\])*"')
_SHARED_NETWORK_RANGE = re.compile(r"\brange\s+[0-9.]+(?:\s+[0-9.]+)?\s*;", re.IGNORECASE)
# Directives anchor on their own line only ([ \t], never \n) so the patterns
# stay linear for the regex analyzer; blank lines directly above a directive
# are consumed by _remove_directives, matching the old ^\s* behaviour.
_RANGE_STATEMENT = re.compile(r"\brange\s++[0-9.]++(?:\s++[0-9.]++)?\s*+;", re.IGNORECASE)
_OPTION_LINE = re.compile(r"(?m)^[ \t]*option\s+[A-Za-z0-9_-]+\s++[^;]*;\s*\n?")
_OPTION_STATEMENT = re.compile(r"(?m)^[ \t]*option\s+([A-Za-z0-9_-]+)\s++([^;]*);")


class PoolScopeEditError(ValueError):
    """A whole-subnet rewrite would discard pool-specific allocation policy."""


def _remove_directives(body: str, pattern: re.Pattern[str]) -> str:
    """Remove each matching directive line and the blank lines directly above it."""
    pieces: list[str] = []
    cursor = 0
    for match in pattern.finditer(body):
        line_start = body.rfind("\n", 0, match.start()) + 1
        while line_start > cursor:
            above = body.rfind("\n", 0, line_start - 1) + 1
            if body[above : line_start - 1].strip():
                break
            line_start = above
        pieces.append(body[cursor:line_start])
        cursor = match.end()
    pieces.append(body[cursor:])
    return "".join(pieces)


def _block(text: str, start: int) -> tuple[int, str]:
    opening = text.index("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1, text[start : index + 1]
    raise ValueError("Unbalanced DHCP configuration block")


def discover_files(main: Path) -> list[Path]:
    """Return the main file and every recursively included configuration file."""
    found: list[Path] = []

    def visit(path: Path) -> None:
        resolved = path.resolve()
        if resolved in found or not resolved.exists():
            return
        found.append(resolved)
        for include in include_names(resolved.read_text(encoding="utf-8")):
            visit(Path(include) if Path(include).is_absolute() else resolved.parent / include)

    visit(main)
    return found


def include_names(text: str) -> list[str]:
    """Find include directives, ignoring comments and unrelated quoted strings."""
    tokens = re.compile(r'#[^\n]*|\binclude\s+"([^"\n]+)"\s*;|"(?:\\.|[^"\\])*"', re.IGNORECASE)
    return [match[1] for match in tokens.finditer(text) if match[1] is not None]


def reservations(text: str, source: str) -> list[dict[str, str]]:
    """Parse reservations with source attribution."""
    result = []
    for match in HOST_START.finditer(text):
        _, body = _block(text, match.start())
        mac = re.search(r"hardware\s+ethernet\s+([0-9A-Fa-f:]{17})\s*;", body)
        address = re.search(r"fixed-address\s+([0-9.]+)\s*;", body)
        if mac and address:
            result.append(
                {
                    "name": match.group(1),
                    "mac": mac.group(1).lower(),
                    "address": address.group(1),
                    "source": source,
                }
            )
    return result


def remove_reservation(text: str, name: str) -> str:
    """Remove one complete host block while preserving surrounding content."""
    for match in HOST_START.finditer(text):
        if match.group(1) == name:
            end, _ = _block(text, match.start())
            return text[: match.start()] + text[end:].lstrip("\n")
    return text


def _shared_network_owns_pool(masked: str, start: int) -> bool:
    """True when a shared-network declares pools at its own scope.

    ISC permits ``range`` statements directly inside a shared-network, not only
    inside nested ``pool { }`` blocks; those pools apply to every enclosed
    subnet, so the agent cannot review them per-subnet. Only allocations at the
    shared-network's own brace depth count: ranges inside nested subnet or pool
    blocks belong to those narrower scopes.
    """
    try:
        opening = masked.index("{", start)
    except ValueError:
        return False
    depth = 1
    index = opening + 1
    direct: list[str] = []
    while index < len(masked):
        char = masked[index]
        if char == "{":
            if depth == 1:
                # A block opened directly in the shared network (e.g. ``pool {
                # {``) scopes the shared network to pool-level allocations and
                # makes every enclosed subnet unsupported for per-subnet review.
                direct.append(char)
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1:
            direct.append(char)
        index += 1
    else:
        return False
    direct_text = "".join(direct)
    return (
        _SHARED_NETWORK_RANGE.search(direct_text) is not None
        or _POOL_START.search(direct_text) is not None
    )


def subnets(text: str) -> list[dict[str, Any]]:
    """Parse subnet ranges and options for editing/export."""
    result = []
    masked = _COMMENTS_AND_STRINGS.sub(lambda m: " " * len(m[0]), text)

    # ISC permits IPv4 pools at shared-network scope. Collect those pools so
    # subnets inside a shared-network that declares pool-level ranges are
    # flagged as unsupported for agent-managed pool review (the agent cannot
    # safely edit pools outside the subnet block).
    shared_pool_networks: set[str] = set()
    for sn_match in _SHARED_NETWORK_START.finditer(masked):
        _sn_end, sn_block = _block(masked, sn_match.start())
        has_pool = _shared_network_owns_pool(sn_block, 0)
        if not has_pool:
            continue
        for subnet_match in SUBNET_START.finditer(sn_block):
            shared_pool_networks.add(subnet_match.group(1))

    for match in SUBNET_START.finditer(masked):
        end, plain = _block(masked, match.start())
        body = text[match.start() : end]
        ranges = [
            [start, finish or start]
            for start, finish in re.findall(
                r"\brange\s+([0-9.]+)(?:\s+([0-9.]+))?\s*;", plain, re.IGNORECASE
            )
        ]
        options = {
            name: value.strip()
            for name, value in re.findall(r"(?m)^[ \t]*option\s+([A-Za-z0-9_-]+)\s++([^;]*);", body)
        }
        entry: dict[str, Any] = {
            "network": match.group(1),
            "netmask": match.group(2),
            "ranges": ranges,
            "options": options,
        }
        if _POOL_START.search(plain):
            # Excluding one reserved address preserves the pool block/ACL, but
            # whole-subnet rewrites would move allocations outside that policy.
            entry["pool_edit_supported"] = False
        if (
            len(ranges) != len(re.findall(r"\brange\b", plain, re.IGNORECASE))
            or re.search(r"\binclude\b", plain, re.IGNORECASE)
            or match.group(1) in shared_pool_networks
        ):
            entry["pool_review_supported"] = False
        result.append(entry)
    return result


def global_options(text: str) -> dict[str, str]:
    """Parse option statements declared outside every subnet and host block.

    ISC applies these top-level options to all subnets unless a subnet
    overrides them, so a migration must carry them into each subnet's
    ``option-data`` or clients lose them.
    """
    spans: list[tuple[int, int]] = []
    for pattern in (SUBNET_START, HOST_START):
        for match in pattern.finditer(text):
            end, _ = _block(text, match.start())
            spans.append((match.start(), end))
    result: dict[str, str] = {}
    for match in _OPTION_STATEMENT.finditer(text):
        if any(start <= match.start() < end for start, end in spans):
            continue
        result[match.group(1)] = match.group(2).strip().strip('"')
    return result


def exclude_address(text: str, network: str, address: str) -> str:
    """Split only allocation statements; retain pool scopes, ACLs and options."""
    masked = _COMMENTS_AND_STRINGS.sub(lambda m: " " * len(m[0]), text)
    for match in SUBNET_START.finditer(masked):
        if match[1] != network:
            continue
        end, body = _block(masked, match.start())
        pattern = re.compile(r"\brange\s+([0-9.]+)(?:\s+([0-9.]+))?\s*;", re.IGNORECASE)
        matches = list(pattern.finditer(body))
        if len(matches) != len(re.findall(r"\brange\b", body, re.IGNORECASE)) or re.search(
            r"\binclude\b", body, re.IGNORECASE
        ):
            raise ValueError("Unsupported allocation syntax; adjust this pool in the native editor")
        original = text[match.start() : end]
        target = int(ipaddress.IPv4Address(address))
        for allocation in reversed(matches):
            start = int(ipaddress.IPv4Address(allocation[1]))
            finish = int(ipaddress.IPv4Address(allocation[2] or allocation[1]))
            if start <= target <= finish:
                intervals = [(start, target - 1), (target + 1, finish)]
                replacement = " ".join(
                    f"range {ipaddress.IPv4Address(left)} {ipaddress.IPv4Address(right)};"
                    for left, right in intervals
                    if left <= right
                )
                original = (
                    original[: allocation.start()] + replacement + original[allocation.end() :]
                )
        return text[: match.start()] + original + text[end:]
    raise ValueError("Unknown subnet")


def update_subnet(text: str, network: str, ranges: list[list[str]], options: dict[str, str]) -> str:
    """Replace ranges and option statements inside one subnet block."""
    masked = _COMMENTS_AND_STRINGS.sub(lambda m: " " * len(m[0]), text)
    for match in SUBNET_START.finditer(masked):
        if match.group(1) != network:
            continue
        end, plain = _block(masked, match.start())
        if _POOL_START.search(plain):
            raise PoolScopeEditError("Pool-scoped allocation policies require the native editor")
        body = text[match.start() : end]
        # Remove complete allocation statements even on compact/inline subnets,
        # without matching commented or quoted examples of range syntax.
        for allocation in reversed(list(_RANGE_STATEMENT.finditer(plain))):
            body = body[: allocation.start()] + body[allocation.end() :]
        body = _remove_directives(body, _OPTION_LINE)
        insertion = "".join(f"  range {start} {finish};\n" for start, finish in ranges)
        insertion += "".join(
            f"  option {name} {value};\n" for name, value in sorted(options.items())
        )
        body = (
            body[: body.index("{") + 1]
            + "\n"
            + insertion
            + body[body.index("{") + 1 :].lstrip("\n")
        )
        return text[: match.start()] + body + text[end:]
    raise KeyError(f"Unknown subnet {network}")


def kea_export(items: list[dict[str, Any]], hosts: list[dict[str, str]]) -> dict[str, Any]:
    """Create a Kea DHCPv4 migration snapshot.

    Each host lands in the first subnet whose prefix contains its address;
    hosts outside every subnet become global reservations (which also sets
    Kea's ``reservations-global``). Subnet ids follow the input order so
    repeated exports stay stable.
    """
    assigned: list[list[dict[str, str]]] = [[] for _ in items]
    global_hosts: list[dict[str, str]] = []
    for host in hosts:
        address = ipaddress.IPv4Address(host["address"])
        for index, item in enumerate(items):
            network = ipaddress.ip_network(f"{item['network']}/{_prefix(item['netmask'])}")
            if address in network:
                assigned[index].append(host)
                break
        else:
            global_hosts.append(host)

    subnets_out = [
        {
            "id": index + 1,
            "subnet": f"{item['network']}/{_prefix(item['netmask'])}",
            "pools": [{"pool": f"{start} - {end}"} for start, end in item["ranges"]],
            "option-data": [
                {"name": name, "data": value.strip('"')}
                for name, value in sorted(item["options"].items())
            ],
            "reservations": [
                {
                    "hostname": host["name"],
                    "hw-address": host["mac"],
                    "ip-address": host["address"],
                }
                for host in assigned[index]
            ],
        }
        for index, item in enumerate(items)
    ]
    snapshot: dict[str, Any] = {"Dhcp4": {"subnet4": subnets_out}}
    if global_hosts:
        snapshot["Dhcp4"]["reservations-global"] = True
        snapshot["Dhcp4"]["reservations"] = [
            {
                "hostname": host["name"],
                "hw-address": host["mac"],
                "ip-address": host["address"],
            }
            for host in global_hosts
        ]
    return snapshot


def _prefix(netmask: str) -> int:
    return sum(bin(int(octet)).count("1") for octet in netmask.split("."))
