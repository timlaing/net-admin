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
)

SOURCES = {
    "radius": (("logins", "RADIUS_AUTH_LOG_FILE"), ("sessions", "RADIUS_ACCOUNTING_DIR")),
    "dhcp": (("leases", "DHCP_LOG_FILE"),),
    "dns": (("ddns", "DNS_UPDATE_LOG_FILE"),),
}


def _detail_files(path: Path) -> list[Path]:
    """Enumerate with explicit permission errors and bounded directory traversal."""
    files = []
    with os.scandir(path) as directories:
        for index, directory in enumerate(directories):
            if index >= 256:
                raise ValueError("Too many accounting directories")
            if not directory.is_dir(follow_symlinks=False):
                continue
            with os.scandir(directory.path) as entries:
                for count, entry in enumerate(entries):
                    if count >= 4096:
                        raise ValueError("Too many accounting directory entries")
                    if (
                        entry.name.startswith("detail-")
                        and not entry.name.endswith((".gz", ".bz2", ".xz"))
                        and entry.is_file(follow_symlinks=False)
                    ):
                        files.append(Path(entry.path))
                        if len(files) > 256:
                            return files
    return files


def _read(kind: str, path: Path | None) -> Any:
    if path is None:
        return jsonify(status="unavailable", rows=[], reason="Log source is not configured.")
    try:
        if kind == "sessions":
            # Only native detail files, never auth-detail files (which may contain secrets).
            files = _detail_files(path)
            if len(files) > 256:
                return jsonify(
                    status="unavailable",
                    rows=[],
                    reason="Accounting source has too many files; archive older detail logs.",
                )
            records = []
            budget = 16_777_216
            for source in sorted(files, key=lambda item: item.stat().st_mtime, reverse=True):
                text = tail(source)
                budget -= len(text.encode("utf-8"))
                if budget < 0:
                    break
                records.extend(accounting_records(text))
            if not path.is_dir():
                raise FileNotFoundError
            rows = session_rows(records, time.time())
        else:
            rows = {"logins": login_rows, "leases": dhcp_rows, "ddns": ddns_rows}[kind](tail(path))
    except (OSError, ValueError, OverflowError):
        return jsonify(
            status="unavailable",
            rows=[],
            reason="Log source cannot be read. Check the agent mount and permissions.",
        )
    return jsonify(
        status="available",
        rows=rows,
        reason=(
            "Recent retained records only; bounded reads may omit older events or session updates."
        ),
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
