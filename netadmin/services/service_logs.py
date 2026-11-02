"""Bounded, allowlisted readers for native service logs; never return raw log lines."""

from __future__ import annotations

import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 2_097_152
MAX_ROWS = 500


def tail(path: Path) -> str:
    """Read a bounded tail, dropping an incomplete leading line."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Log source must be a regular file")
        size = stream.seek(0, 2)
        stream.seek(max(0, size - MAX_BYTES))
        data = stream.read(MAX_BYTES)
    if size > MAX_BYTES:
        data = data.partition(b"\n")[2]
    return data.decode("utf-8", errors="replace")


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
    # A trailing blank line marks a complete record; do not consume a partial write.
    for block in re.split(r"\r?\n\s*\r?\n", text)[:-1]:
        record = {}
        for key, value in re.findall(r"^\s*([\w-]+) = (.*?)\s*$", block, re.MULTILINE):
            if key in allowed:
                record[key] = value.strip('"')[:256]
        if record.get("Timestamp", "").isdigit():
            records.append(record)
    return records


def session_rows(records: list[dict[str, str]], now: float) -> list[dict[str, str]]:
    """Fold accounting by NAS/session identity; mark silent sessions stale after 15 minutes."""
    sessions: dict[tuple[str, str], dict[str, str]] = {}
    for record in sorted(records, key=lambda item: int(item["Timestamp"])):
        nas = record.get(
            "NAS-IP-Address",
            record.get("NAS-IPv6-Address", record.get("Packet-Src-IP-Address", "")),
        )
        identifier = record.get("Acct-Unique-Session-Id", record.get("Acct-Session-Id", ""))
        status = record.get("Acct-Status-Type", "")
        if nas and status in {"Accounting-On", "Accounting-Off"}:
            for (session_nas, _), existing in sessions.items():
                if session_nas == nas and existing["Acct-Status-Type"] != "Stop":
                    existing["_uncertain"] = "yes"
            continue
        if not nas or not identifier or status not in {"Start", "Stop", "Interim-Update"}:
            continue
        key = (nas, identifier)
        if status == "Start":
            sessions[key] = {"_started": record["Timestamp"]}
        merged = sessions.setdefault(key, {})
        merged.update(record)
    rows = []
    for (nas, identifier), record in sessions.items():
        updated = int(record["Timestamp"])
        if not 0 <= updated <= 253402214400:
            continue
        duration = record.get("Acct-Session-Time", "")
        start = (
            int(record["_started"])
            if "_started" in record
            else updated - int(duration)
            if duration.isdigit()
            else None
        )
        status = record["Acct-Status-Type"]
        rows.append(
            {
                "user": record.get("User-Name", ""),
                "session": identifier,
                "client": nas,
                "device": record.get("Calling-Station-Id", ""),
                "access_point": record.get("Called-Station-Id", ""),
                "address": record.get("Framed-IP-Address", ""),
                "started": _utc(start)
                if start is not None and start >= 0
                else (_utc(updated) if status == "Start" else "Unknown"),
                "ended": _utc(updated) if status == "Stop" else "",
                "updated": _utc(updated),
                "duration": duration,
                "received": _octets(record, "Input"),
                "sent": _octets(record, "Output"),
                "status": "Ended"
                if status == "Stop"
                else ("Stale" if now - updated > 900 or record.get("_uncertain") else "Active"),
            }
        )
    return sorted(rows, key=lambda row: row["updated"], reverse=True)[:MAX_ROWS]


def _utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _octets(record: dict[str, str], direction: str) -> str:
    low = record.get(f"Acct-{direction}-Octets", "")
    high = record.get(f"Acct-{direction}-Gigawords", "0")
    return str(int(low) + (int(high) << 32)) if low.isdigit() and high.isdigit() else ""
