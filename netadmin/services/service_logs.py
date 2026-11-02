"""Bounded, allowlisted readers for native service logs; never return raw log lines."""

from __future__ import annotations

import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 2_097_152
MAX_ROWS = 500


DETAIL_HEADER = re.compile(
    r"[A-Za-z]{3} [A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}"
)
MAX_EPOCH = 253402300799


def tail_chunk(path: Path, limit: int, *, accounting: bool = False) -> tuple[str, int]:
    """Return complete leading lines/blocks and charge all bytes read to the budget."""
    limit = min(MAX_BYTES + 1, limit)
    if limit <= 0:
        return "", 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Log source must be a regular file")
        size = stream.seek(0, 2)
        payload_limit = min(MAX_BYTES, limit)
        if size > payload_limit:
            payload_limit = min(MAX_BYTES, limit - 1)
        offset = max(0, size - payload_limit)
        stream.seek(max(0, offset - 1))
        data = stream.read(payload_limit + int(offset > 0))
    consumed = len(data)
    # Include a look-behind byte inside the same budget when the source is truncated.
    if offset:
        previous, data = data[:1], data[1:]
        if previous != b"\n":
            data = data.partition(b"\n")[2]
    text = data.decode("utf-8", errors="replace")
    if accounting:
        lines = text.splitlines(keepends=True)
        first = next(
            (
                index
                for index, line in enumerate(lines)
                if DETAIL_HEADER.fullmatch(line.rstrip("\r\n"))
            ),
            len(lines),
        )
        text = "".join(lines[first:])
    return text, consumed


def tail(path: Path) -> str:
    """Read a bounded tail of complete event lines."""
    return tail_chunk(path, MAX_BYTES + 1)[0]


def timestamp(line: str) -> str:
    """Preserve the daemon's timestamp, including its original timezone if present."""
    patterns = (
        r"^\w{3} \w{3}\s+\d+ \d\d:\d\d:\d\d \d{4}",
        r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:\d\d)?",
        r"^\d\d?-\w{3}-\d{4} \d\d:\d\d:\d\d(?:\.\d+)?",
        r"^\w{3}\s+\d+ \d\d:\d\d:\d\d",
    )
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            return match[0]
    return "Unknown"


def login_rows(text: str) -> list[dict[str, str]]:
    """Extract FreeRADIUS auth results without passwords or failure-message contents."""
    rows = []
    pattern = re.compile(
        r"Login (OK|incorrect)(?: \([^\r\n]*?\))?: \[([^\]/\r\n]+)(?:/[^\]\r\n]*)?\]"
        r" \(from client ([\w.:-]+) port [\w.-]+(?: cli ([\w.:-]+))?"
    )
    for line in text.splitlines():
        match = pattern.search(line)
        if match:
            rows.append(
                {
                    "when": timestamp(line),
                    "user": match[2],
                    "client": match[3],
                    "device": match[4] or "",
                    "result": "Accepted" if match[1] == "OK" else "Rejected",
                }
            )
    return rows[-MAX_ROWS:][::-1]


def dhcp_rows(text: str) -> list[dict[str, str]]:
    """Extract ISC lease acknowledgements/releases and Kea committed leases."""
    rows = []
    for line in text.splitlines():
        match = re.search(
            r"(DHCPACK|DHCPRELEASE|DHCPNAK) (?:on |of )?([\d.]+) "
            r"(?:to|from) ([0-9a-fA-F:]+)(?: \(([^)\r\n]*)\))?(?: (?:via|on) ([\w.:-]+))?",
            line,
        )
        if match:
            rows.append(
                {
                    "when": timestamp(line),
                    "action": match[1],
                    "address": match[2],
                    "device": match[3],
                    "hostname": match[4] or "",
                    "client": match[5] or "",
                }
            )
            continue
        if "DHCP4_LEASE_ALLOC" in line or "DHCP4_LEASE_REUSE" in line:
            address = re.search(r"lease ([\d.]+)", line)
            hardware = re.search(r"hwtype=\d+ ([0-9a-fA-F:]+)", line)
            if address and hardware:
                rows.append(
                    {
                        "when": timestamp(line),
                        "action": "Lease committed",
                        "address": address[1],
                        "device": hardware[1],
                        "hostname": "",
                        "client": "",
                    }
                )
    return rows[-MAX_ROWS:][::-1]


def ddns_rows(text: str) -> list[dict[str, str]]:
    """Extract BIND update mutations; deleted values are often absent in BIND logs."""
    rows = []
    pattern = re.compile(
        r"updating zone '([^'\r\n]+)': (adding an RR at|deleting rrset at|deleting an RR at) "
        r"'([^'\r\n]+)' ([A-Z0-9]+)(?: ([^\r\n]*))?"
    )
    for line in text.splitlines():
        match = pattern.search(line)
        if match:
            client = re.search(r"client (?:@\S+ )?([\da-fA-F:.]+)#\d+", line)
            rows.append(
                {
                    "when": timestamp(line),
                    "zone": match[1],
                    "action": "Add" if match[2].startswith("adding") else "Delete",
                    "name": match[3],
                    "type": match[4],
                    "value": match[5] or "",
                    "client": client[1] if client else "",
                }
            )
    return rows[-MAX_ROWS:][::-1]


def accounting_records(text: str) -> list[dict[str, str]]:
    """Parse complete native FreeRADIUS detail blocks, ignoring arbitrary attributes."""
    allowed = {
        "User-Name",
        "Acct-Session-Id",
        "Acct-Unique-Session-Id",
        "NAS-IP-Address",
        "NAS-IPv6-Address",
        "Packet-Src-IP-Address",
        "Calling-Station-Id",
        "Called-Station-Id",
        "Framed-IP-Address",
        "Acct-Status-Type",
        "Timestamp",
        "Acct-Session-Time",
        "Acct-Input-Octets",
        "Acct-Output-Octets",
        "Acct-Input-Gigawords",
        "Acct-Output-Gigawords",
    }
    records = []
    block: list[str] = []
    for line in text.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            record = _accounting_record(block, allowed)
            if record:
                records.append(record)
            block = []
    return records


def _accounting_record(lines: list[str], allowed: set[str]) -> dict[str, str]:
    if not DETAIL_HEADER.fullmatch(lines[0]):
        return {}
    record = {}
    for line in lines[1:]:
        key, separator, value = line.strip().partition(" = ")
        if separator and key in allowed:
            record[key] = value.strip('"')[:256]
    return record if _epoch(record) is not None else {}


def _decimal(value: str) -> int | None:
    return int(value) if re.fullmatch(r"[0-9]{1,20}", value) else None


def _epoch(record: dict[str, str]) -> int | None:
    value = _decimal(record.get("Timestamp", ""))
    return value if value is not None and value <= MAX_EPOCH else None


def _nas(record: dict[str, str]) -> str:
    return (
        record.get("NAS-IP-Address")
        or record.get("NAS-IPv6-Address")
        or record.get("Packet-Src-IP-Address", "")
    )


def _aliases(records: list[dict[str, str]]) -> dict[tuple[str, str], tuple[str, str]]:
    links: dict[tuple[str, str], set[str]] = {}
    for record in records:
        short = record.get("Acct-Session-Id", "")
        unique = record.get("Acct-Unique-Session-Id", "")
        if short and unique:
            links.setdefault((_nas(record), short), set()).add(unique)
    return {key: (key[0], next(iter(values))) for key, values in links.items() if len(values) == 1}


def _key(
    record: dict[str, str],
    aliases: dict[tuple[str, str], tuple[str, str]],
    current: dict[tuple[str, str], tuple[str, str]],
) -> tuple[str, str] | None:
    nas = _nas(record)
    short = record.get("Acct-Session-Id", "")
    unique = record.get("Acct-Unique-Session-Id", "")
    if not nas or not (short or unique):
        return None
    short_key = (nas, short)
    if not unique:
        return aliases.get(short_key, current.get(short_key, short_key))
    key = (nas, unique)
    if short and (record["Acct-Status-Type"] == "Start" or short_key not in current):
        current[short_key] = key
    return key


def _reset_nas(sessions: dict[tuple[str, str], dict[str, str]], nas: str) -> None:
    for (session_nas, _), existing in sessions.items():
        if session_nas == nas and existing["Acct-Status-Type"] != "Stop":
            existing["_uncertain"] = "yes"


def session_rows(records: list[dict[str, str]], now: float) -> list[dict[str, str]]:
    """Fold valid records by NAS identity with deterministic same-second status ordering."""
    valid = [record for record in records if _epoch(record) is not None]
    order = {"Accounting-On": -1, "Accounting-Off": -1, "Start": 0, "Interim-Update": 1, "Stop": 2}
    valid.sort(
        key=lambda item: (int(item["Timestamp"]), order.get(item.get("Acct-Status-Type", ""), 3))
    )
    sessions: dict[tuple[str, str], dict[str, str]] = {}
    aliases = _aliases(valid)
    current: dict[tuple[str, str], tuple[str, str]] = {}
    for record in valid:
        status = record.get("Acct-Status-Type", "")
        if status in {"Accounting-On", "Accounting-Off"}:
            _reset_nas(sessions, _nas(record))
        elif status in {"Start", "Stop", "Interim-Update"}:
            _fold_record(sessions, record, aliases, current)
    rows = [
        _session_row(nas, identifier, record, now) for (nas, identifier), record in sessions.items()
    ]
    return sorted(rows, key=lambda row: row["updated"], reverse=True)[:MAX_ROWS]


def _fold_record(
    sessions: dict[tuple[str, str], dict[str, str]],
    record: dict[str, str],
    aliases: dict[tuple[str, str], tuple[str, str]],
    current: dict[tuple[str, str], tuple[str, str]],
) -> None:
    key = _key(record, aliases, current)
    if key is None:
        return
    short_key = (_nas(record), record.get("Acct-Session-Id", ""))
    if key != short_key and short_key in sessions and key not in sessions:
        sessions[key] = sessions.pop(short_key)
    if record["Acct-Status-Type"] == "Start":
        sessions[key] = {"_started": record["Timestamp"]}
    sessions.setdefault(key, {}).update(record)


def _started(record: dict[str, str], updated: int) -> str:
    start = _decimal(record.get("_started", ""))
    duration = _decimal(record.get("Acct-Session-Time", ""))
    if start is None and duration is not None:
        start = updated - duration
    if start is None or not 0 <= start <= MAX_EPOCH:
        return "Unknown"
    return _utc(start)


def _session_row(nas: str, identifier: str, record: dict[str, str], now: float) -> dict[str, str]:
    updated = int(record["Timestamp"])
    status = "Active"
    ended = ""
    if record["Acct-Status-Type"] == "Stop":
        status = "Ended"
        ended = _utc(updated)
    elif now - updated > 900 or record.get("_uncertain"):
        status = "Stale"
    duration = record.get("Acct-Session-Time", "")
    return {
        "user": record.get("User-Name", ""),
        "session": identifier,
        "client": nas,
        "device": record.get("Calling-Station-Id", ""),
        "access_point": record.get("Called-Station-Id", ""),
        "address": record.get("Framed-IP-Address", ""),
        "started": _started(record, updated),
        "ended": ended,
        "updated": _utc(updated),
        "duration": duration if _decimal(duration) is not None else "",
        "received": _octets(record, "Input"),
        "sent": _octets(record, "Output"),
        "status": status,
    }


def _utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _octets(record: dict[str, str], direction: str) -> str:
    low = _decimal(record.get(f"Acct-{direction}-Octets", ""))
    high = _decimal(record.get(f"Acct-{direction}-Gigawords", "0"))
    return str(low + (high << 32)) if low is not None and high is not None else ""
