"""Loss-minimizing subnet creation/removal in existing daemon configuration."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator

from netadmin.services import dhcp_files, kea_files


def _code_matches(text: str, pattern: re.Pattern[str]) -> Iterator[re.Match[str]]:
    """Ignore apparent declarations inside comments or quoted values."""
    position = 0
    while position < len(text):
        match = pattern.match(text, position)
        if match:
            yield match
            position = match.end()
        else:
            skipped = kea_files._skip(text, position)  # pylint: disable=protected-access
            position = skipped if skipped is not None else position + 1


def _next_token(text: str, position: int) -> int:
    """Skip whitespace and comments between array items."""
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        if text[position] != '"':
            skipped = kea_files._skip(text, position)  # pylint: disable=protected-access
            if skipped is not None:
                position = skipped
                continue
        break
    return position


def create_subnet(text: str, cidr: str, identifier: int, kea: bool) -> str:
    """Add an empty allocation subnet; pools can then be added independently."""
    network = ipaddress.IPv4Network(cidr)
    if not kea:
        return text + f"\nsubnet {network.network_address} netmask {network.netmask} {{\n}}\n"
    arrays = list(_code_matches(text, re.compile(r'"subnet4"\s*:\s*\[')))
    if len(arrays) != 1:
        raise ValueError("Exactly one subnet4 array is required in the main Kea configuration")
    opening = arrays[0].end()
    # The daemon validates the complete candidate before it is accepted.
    suffix = text[opening:]
    item = json.dumps({"id": identifier, "subnet": str(network), "pools": []})
    position = _next_token(text, opening)
    separator = "" if text[position : position + 1] == "]" else ","
    return text[:opening] + "\n" + item + separator + suffix


def _kea_removal_span(text: str, match: re.Match[str]) -> tuple[int, int]:
    """Include the adjacent array separator when removing a Kea object."""
    start, end = kea_files._enclosing_object(text, match)  # pylint: disable=protected-access
    following = _next_token(text, end)
    if text[following : following + 1] == ",":
        return start, following + 1
    preceding = start - 1
    while preceding >= 0 and text[preceding].isspace():
        preceding -= 1
    if preceding >= 0 and text[preceding] == ",":
        start = preceding
    return start, end


def remove_subnet(text: str, network: str, kea: bool) -> str:
    """Remove only the selected subnet, retaining unrelated directives."""
    pattern = kea_files.SUBNET_VALUE if kea else dhcp_files.SUBNET_START
    for match in _code_matches(text, pattern):
        if match.group(1).split("/")[0] != network:
            continue
        if kea:
            start, end = _kea_removal_span(text, match)
        else:
            start = match.start()
            end, _ = dhcp_files._block(text, start)  # pylint: disable=protected-access
        return text[:start] + text[end:]
    raise ValueError("Unknown subnet")
