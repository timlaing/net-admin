"""Read-only service telemetry endpoints with operator-selected sources."""

from __future__ import annotations

import os
import time
from functools import partial
from pathlib import Path
from typing import Any

from flask import Flask, jsonify

from netadmin.agents.common import configured_path
from netadmin.services.service_logs import (
    accounting_records,
    ddns_rows,
    dhcp_rows,
    login_rows,
    session_rows,
    tail,
    tail_chunk,
)

SOURCES = {
    "radius": (("logins", "RADIUS_AUTH_LOG_FILE"), ("sessions", "RADIUS_ACCOUNTING_DIR")),
    "dhcp": (("leases", "DHCP_LOG_FILE"),),
    "dns": (("ddns", "DNS_UPDATE_LOG_FILE"),),
}
ACCOUNTING_BUDGET = 16_777_216


class RetentionLimit(ValueError):
    """The source exceeds explicit file or directory traversal limits."""


def _nas_files(path: str) -> list[Path]:
    files = []
    try:
        with os.scandir(path) as entries:
            for count, entry in enumerate(entries):
                if count >= 4096:
                    raise RetentionLimit("Accounting directory entry limit exceeded")
                if (
                    entry.name.startswith("detail-")
                    and not entry.name.endswith((".gz", ".bz2", ".xz"))
                    and entry.is_file(follow_symlinks=False)
                ):
                    files.append(Path(entry.path))
                    if len(files) > 256:
                        raise RetentionLimit("Accounting file limit exceeded")
    except FileNotFoundError:
        return []  # A NAS directory can disappear during rotation.
    return files


def _detail_files(path: Path) -> list[Path]:
    """Enumerate without following symlinks, bounding every directory traversal."""
    files = []
    with os.scandir(path) as directories:
        for index, directory in enumerate(directories):
            if index >= 256:
                raise RetentionLimit("Accounting directory limit exceeded")
            if directory.is_dir(follow_symlinks=False):
                files.extend(_nas_files(directory.path))
                if len(files) > 256:
                    raise RetentionLimit("Accounting file limit exceeded")
    return files


def _ordered_files(files: list[Path]) -> list[Path]:
    retained = []
    for source in files:
        try:
            retained.append((source.stat().st_mtime, str(source), source))
        except OSError:
            continue
    return [item[2] for item in sorted(retained, reverse=True)]


def _sessions(path: Path) -> list[dict[str, str]]:
    candidates = _detail_files(path)
    files = _ordered_files(candidates)
    if candidates and not files:
        raise OSError("Accounting files changed during enumeration")
    records = []
    budget = ACCOUNTING_BUDGET
    readable = 0
    for source in files:
        if budget <= 0:
            break
        try:
            text, consumed = tail_chunk(source, budget, accounting=True)
        except OSError:
            continue
        readable += 1
        budget -= consumed
        records.extend(accounting_records(text))
    if not path.is_dir() or (files and not readable):
        raise OSError("Accounting files are unavailable")
    return session_rows(records, time.time())


def _event_text(path: Path) -> str:
    try:
        return tail(path)
    except OSError:
        return tail(path)  # Retry once if rotation replaced the current event log.


def _read(kind: str, path: Path | None) -> Any:
    if path is None:
        return jsonify(status="unavailable", rows=[], reason="Log source is not configured.")
    try:
        if kind == "sessions":
            rows = _sessions(path)
        else:
            rows = {"logins": login_rows, "leases": dhcp_rows, "ddns": ddns_rows}[kind](
                _event_text(path)
            )
    except RetentionLimit:
        return jsonify(
            status="unavailable",
            rows=[],
            reason="Accounting source exceeds retention limits; archive older detail logs "
            "or reduce the number of NAS directories and entries.",
        )
    except (OSError, ValueError, OverflowError):
        return jsonify(
            status="unavailable",
            rows=[],
            reason="Log source cannot be read. Check the agent mount and permissions.",
        )
    return jsonify(
        status="available",
        rows=rows,
        reason="Recent retained records only; bounded reads may omit older events "
        "or session updates.",
    )


def register_logs(app: Flask, service: str) -> None:
    """Register only the corresponding agent's fixed read endpoints."""
    for kind, variable in SOURCES[service]:
        path = configured_path(variable, "/unused") if os.getenv(variable) else None
        app.add_url_rule(
            f"/logs/{kind}",
            endpoint=f"logs_{kind}",
            view_func=partial(_read, kind, path),
            methods=["GET"],
        )
