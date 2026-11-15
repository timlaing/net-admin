"""Kea DHCPv4 configuration assembly, transforms and memfile lease parsing.

Kea configuration is extended JSON: line/block comments and
``<?include "file"?>`` directives are allowed, so text operations are built
on bracket matching that skips strings and comments instead of plain
``json.loads``. The NetAdmin-managed reservations file is regenerated
wholesale on every change, which keeps those round trips lossless.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

INCLUDE = re.compile(r'<\?include\s+"([^"]+)"\?>')
SUBNET_VALUE = re.compile(r'"subnet"\s*:\s*"([\d.]+/\d+)"')
_POOLS_KEY = re.compile(r'"pools"\s*:\s*\[')
_OPTION_DATA_KEY = re.compile(r'"option-data"\s*:\s*\[')
_RESERVATIONS_KEY = re.compile(r'"reservations"\s*:\s*\[')
_SUBNET_ID = re.compile(r'"id"\s*:\s*(\d+)')

# Kea memfile lease states from src/lib/dhcpsrv/lease.h (STATE_* constants),
# named with the ISC binding-state vocabulary the web UI already displays.
STATE_NAMES = {
    "0": "active",
    "1": "declined",
    "2": "expired",
    "3": "released",
    "4": "registered",
}


def _after_string(text: str, index: int) -> int:
    """Index just after the string literal whose opening quote is at index."""
    position = index + 1
    while position < len(text):
        character = text[position]
        if character == "\\":
            position += 2
            continue
        if character == '"':
            return position + 1
        position += 1
    raise ValueError("Unterminated string in Kea configuration")


def _skip(text: str, position: int) -> int | None:
    """Index after the string or comment at position, else None for plain text."""
    if text[position] == '"':
        return _after_string(text, position)
    if text[position] == "#" or text.startswith("//", position):
        newline = text.find("\n", position)
        return len(text) if newline < 0 else newline + 1
    if text.startswith("/*", position):
        closing = text.find("*/", position + 2)
        if closing < 0:
            raise ValueError("Unterminated comment in Kea configuration")
        return closing + 2
    return None


def _match_block(text: str, opening: int, opener: str, closer: str) -> int:
    """Index after the bracket matching text[opening], ignoring strings/comments."""
    depth = 0
    position = opening
    while position < len(text):
        skipped = _skip(text, position)
        if skipped is not None:
            position = skipped
            continue
        character = text[position]
        if character == opener:
            depth += 1
        elif character == closer:
            depth -= 1
            if depth == 0:
                return position + 1
        position += 1
    raise ValueError("Unbalanced Kea configuration block")


def _arrays(text: str, pattern: re.Pattern[str]) -> list[tuple[int, int]]:
    """Start (at the bracket) and end (after it) of every array matching pattern."""
    return [
        (match.end() - 1, _match_block(text, match.end() - 1, "[", "]"))
        for match in pattern.finditer(text)
    ]


def _objects(text: str, start: int, end: int) -> list[Any]:
    """Parse each object literal between start and end, skipping trivia."""
    result: list[Any] = []
    position = start
    while position < end:
        skipped = _skip(text, position)
        if skipped is not None:
            position = skipped
            continue
        if text[position] == "{":
            closing = _match_block(text, position, "{", "}")
            try:
                result.append(json.loads(text[position:closing]))
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid Kea object: {error}") from error
            position = closing
            continue
        position += 1
    return result


def _enclosing_object(text: str, match: re.Match[str]) -> tuple[int, int]:
    """Bounds of the innermost object that fully contains the match."""
    opening = text.rfind("{", 0, match.start())
    while opening >= 0:
        end = _match_block(text, opening, "{", "}")
        if opening < match.start() and match.end() <= end:
            return opening, end
        opening = text.rfind("{", 0, opening)
    raise ValueError("Kea key found outside an object")


def _array_items(body: str, pattern: re.Pattern[str]) -> list[Any]:
    """Objects of the first array following a key inside body, or an empty list."""
    found = _arrays(body, pattern)
    if not found:
        return []
    start, end = found[0]
    return _objects(body, start + 1, end - 1)


def discover_files(main: Path) -> list[Path]:
    """Return the main file and every recursively included configuration file."""
    found: list[Path] = []

    def visit(path: Path) -> None:
        resolved = path.resolve()
        if resolved in found or not resolved.exists():
            return
        found.append(resolved)
        for include in INCLUDE.findall(resolved.read_text(encoding="utf-8")):
            visit(Path(include) if Path(include).is_absolute() else resolved.parent / include)

    visit(main)
    return found


def parse_reservations(text: str) -> list[dict[str, str]]:
    """Parse the supported Kea reservation subset from every scope."""
    result = []
    for start, end in _arrays(text, _RESERVATIONS_KEY):
        for item in _objects(text, start + 1, end - 1):
            if not isinstance(item, dict):
                continue
            mac = str(item.get("hw-address", "")).lower()
            address = str(item.get("ip-address", ""))
            if mac and address:
                result.append(
                    {
                        "name": str(item.get("hostname", "")),
                        "mac": mac,
                        "address": address,
                    }
                )
    return result


def reservations(text: str, source: str) -> list[dict[str, str]]:
    """Parse reservations with source attribution."""
    return [entry | {"source": source} for entry in parse_reservations(text)]


def render_reservations(items: list[dict[str, str]]) -> str:
    """Render the deterministic NetAdmin-managed Kea reservations file.

    Kea's include directive splices bare members into the surrounding map,
    so the file is a ``"reservations": [...]`` member, not a standalone
    JSON document (outer braces are a 3.0.3 syntax error in include files).
    """
    payload = json.dumps(
        [
            {
                "hostname": item["name"],
                "hw-address": item["mac"],
                "ip-address": item["address"],
            }
            for item in sorted(items, key=lambda value: value["name"])
        ],
        indent=2,
    )
    return (
        '# Managed by NetAdmin. Manual changes may be replaced.\n\n"reservations": '
        + payload
        + "\n"
    )


def remove_reservation(text: str, name: str) -> str:
    """Drop one host from the managed reservations file, keeping the header."""
    parsed = parse_reservations(text)
    if not any(entry["name"] == name for entry in parsed):
        return text
    return render_reservations([entry for entry in parsed if entry["name"] != name])


def subnets(text: str) -> list[dict[str, Any]]:
    """Parse subnet pools, options and identity for editing/export."""
    result: list[dict[str, Any]] = []
    for match in SUBNET_VALUE.finditer(text):
        opening, end = _enclosing_object(text, match)
        body = text[opening:end]
        cidr = match.group(1)
        entry: dict[str, Any] = {
            "network": cidr.split("/", maxsplit=1)[0],
            "netmask": str(ipaddress.ip_network(cidr).netmask),
            "ranges": [
                pool_range(str(item["pool"]))
                for item in _array_items(body, _POOLS_KEY)
                if isinstance(item, dict) and "pool" in item
            ],
            "options": {
                str(item["name"]): str(item["data"])
                for item in _array_items(body, _OPTION_DATA_KEY)
                if isinstance(item, dict) and "name" in item and "data" in item
            },
        }
        if INCLUDE.search(body):
            entry["pool_review_supported"] = False
        identifier = _SUBNET_ID.search(body)
        if identifier:
            entry["id"] = int(identifier.group(1))
        result.append(entry)
    return result


def pool_range(value: str) -> list[str]:
    """Normalize Kea interval, singleton and CIDR pools without losing metadata."""
    if "/" in value:
        network = ipaddress.IPv4Network(value.strip())
        return [str(network.network_address), str(network.broadcast_address)]
    parts = value.split("-", maxsplit=1)
    start = str(ipaddress.IPv4Address(parts[0].strip()))
    finish = str(ipaddress.IPv4Address(parts[-1].strip()))
    return [start, finish]


def exclude_address(text: str, network: str, address: str) -> str:
    """Split the selected pools, carrying every pool-specific setting forward."""
    target = int(ipaddress.IPv4Address(address))
    for match in SUBNET_VALUE.finditer(text):
        if match[1].split("/", maxsplit=1)[0] != network:
            continue
        opening, end = _enclosing_object(text, match)
        body = text[opening:end]
        pools: list[dict[str, Any]] = []
        for pool in _array_items(body, _POOLS_KEY):
            start, finish = (int(ipaddress.IPv4Address(v)) for v in pool_range(pool["pool"]))
            if start <= target <= finish:
                pools.extend(
                    pool
                    | {"pool": f"{ipaddress.IPv4Address(left)} - {ipaddress.IPv4Address(right)}"}
                    for left, right in ((start, target - 1), (target + 1, finish))
                    if left <= right
                )
            else:
                pools.append(pool)
        updated = _replace_array(body, _POOLS_KEY, json.dumps(pools, indent=2))
        if updated is None:
            raise ValueError("Pool definition is not editable")
        return text[:opening] + updated + text[end:]
    raise ValueError("Unknown subnet")


def _replace_array(body: str, pattern: re.Pattern[str], replacement: str) -> str | None:
    """Replace the array after a key with a rendered ``[...]``, else None."""
    found = _arrays(body, pattern)
    if not found:
        return None
    start, end = found[0]
    return body[:start] + replacement + body[end:]


def update_subnet(text: str, network: str, ranges: list[list[str]], options: dict[str, str]) -> str:
    """Replace a subnet's pools and option-data while preserving everything else."""
    pools = json.dumps([{"pool": f"{start} - {finish}"} for start, finish in ranges], indent=4)
    data = json.dumps(
        [{"name": name, "data": value} for name, value in sorted(options.items())],
        indent=4,
    )
    for match in SUBNET_VALUE.finditer(text):
        if match.group(1).split("/", maxsplit=1)[0] != network:
            continue
        opening, end = _enclosing_object(text, match)
        body = text[opening:end]
        for pattern, key, rendered in (
            (_POOLS_KEY, "pools", pools),
            (_OPTION_DATA_KEY, "option-data", data),
        ):
            updated = _replace_array(body, pattern, rendered)
            if updated is None:
                body = body[:1] + f'\n    "{key}": {rendered},' + body[1:]
            else:
                body = updated
        return text[:opening] + body + text[end:]
    raise KeyError(f"Unknown subnet {network}")


def parse_leases(text: str) -> list[dict[str, str]]:
    """Parse useful fields from a Kea memfile CSV lease database."""
    leases: list[dict[str, str]] = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#") or row[0] == "address":
            continue
        if len(row) < 10:
            continue
        address, mac, _client_id, _lifetime, expire, _subnet, _fwd, _rev, hostname, state = row[:10]
        state = state.strip()
        leases.append(
            {
                "address": address,
                "state": STATE_NAMES.get(state, state),
                "mac": mac,
                "hostname": hostname,
                "ends": expire,
            }
        )
    return leases
