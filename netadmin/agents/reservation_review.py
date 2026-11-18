"""Stateless, expiring approval bound to a reservation and its config snapshot."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import time
from pathlib import Path
from typing import Any

INPUT_MESSAGES = {
    "overlap": "Address belongs to overlapping subnets; correct the configuration first",
    "outside": "Address is outside every configured subnet/VLAN",
    "selection": "The address does not belong to the selected subnet/VLAN",
    "unsupported": "Allocation includes or syntax cannot be reviewed safely; "
    "adjust the pool natively first",
    "boundary": "A reservation cannot use a network or broadcast address",
}


class ReservationInputError(ValueError):
    """A trusted validation code, distinct from native/configuration diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(self.safe_message())

    def safe_message(self) -> str:
        """Only known literal messages may cross the agent boundary."""
        return INPUT_MESSAGES.get(
            self.code, "Reservation validation failed; review the input again"
        )


def public_validation_message(error: ValueError) -> str:
    """Never serialize an unexpected native/configuration exception."""
    if isinstance(error, ReservationInputError):
        return error.safe_message()
    return (
        "Subnet or pool configuration could not be reviewed safely. "
        "Check the agent configuration; no changes were applied."
    )


def select_subnet(
    subnets: list[dict[str, Any]], address: str, selected: str
) -> dict[str, Any] | None:
    """Never choose an overlapping subnet or accept a mismatching explicit selection."""
    ip = ipaddress.IPv4Address(address)
    matches = [s for s in subnets if ip in ipaddress.IPv4Network(f"{s['network']}/{s['netmask']}")]
    if len(matches) > 1:
        raise ReservationInputError("overlap")
    subnet = matches[0] if matches else None
    if subnets and subnet is None:
        raise ReservationInputError("outside")
    if selected and (subnet is None or selected != subnet["network"]):
        raise ReservationInputError("selection")
    if subnet:
        if subnet.get("pool_review_supported") is False:
            raise ReservationInputError("unsupported")
        network = ipaddress.IPv4Network(f"{subnet['network']}/{subnet['netmask']}")
        if ip in (network.network_address, network.broadcast_address):
            raise ReservationInputError("boundary")
    return subnet


def adjusted_ranges(ranges: list[list[str]], address: str) -> list[list[str]]:
    """Remove only one address from every interval that contains it."""
    target = int(ipaddress.IPv4Address(address))
    result: list[list[str]] = []
    for first, last in ranges:
        start, finish = int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last))
        intervals = (
            ((start, target - 1), (target + 1, finish))
            if start <= target <= finish
            else ((start, finish),)
        )
        result.extend(
            [str(ipaddress.IPv4Address(left)), str(ipaddress.IPv4Address(right))]
            for left, right in intervals
            if left <= right
        )
    return result


def approval(
    item: dict[str, str], originals: dict[Path, bytes | None], issued: int | None = None
) -> str:
    """Authenticate the exact preview without storing configuration or secrets in SQLite."""
    timestamp = int(time.time()) if issued is None else issued
    digest = hashlib.sha256(json.dumps(item, sort_keys=True).encode())
    for path, content in sorted(originals.items()):
        digest.update(str(path).encode())
        digest.update(hashlib.sha256(content or b"").digest())
    message = f"{timestamp}:{digest.hexdigest()}".encode()
    signature = hmac.new(
        os.environ["NETADMIN_AGENT_TOKEN"].encode(), message, hashlib.sha256
    ).hexdigest()
    return f"{timestamp}.{signature}"


def approved(token: str, item: dict[str, str], originals: dict[Path, bytes | None]) -> bool:
    """Reject expiry, payload edits and concurrent native configuration changes."""
    try:
        issued = int(token.split(".", maxsplit=1)[0])
    except ValueError:
        return False
    return 0 <= time.time() - issued <= 900 and hmac.compare_digest(
        token, approval(item, originals, issued)
    )
