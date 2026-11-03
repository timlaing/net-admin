"""Indexed public certificate inventory; never stores keys or configuration."""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature


class CertificateInventory:
    """Keep cursor reads bounded after a one-time import of legacy public PEMs."""

    def __init__(self, root: Path):
        self.path = root / "certificate-inventory.sqlite"

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Open a private, short-lived transaction with bounded failure messages."""
        with contextlib.suppress(FileExistsError):
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        try:
            with contextlib.closing(sqlite3.connect(self.path)) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS certificates (authority TEXT NOT NULL, "
                    "id TEXT NOT NULL, pem TEXT NOT NULL, PRIMARY KEY(authority, id))"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS imported (authority TEXT PRIMARY KEY)"
                )
                yield connection
                connection.commit()
        except sqlite3.Error as error:
            raise OSError("Public certificate inventory unavailable") from error

    def record(self, directory: Path, operation_id: str, pem: str) -> None:
        """Index verified public output before reporting a completed signing operation."""
        with self.connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?)",
                (directory.name, operation_id, pem),
            )

    @staticmethod
    def _import_legacy(connection: sqlite3.Connection, directory: Path) -> None:
        if connection.execute(
            "SELECT 1 FROM imported WHERE authority=?", (directory.name,)
        ).fetchone():
            return
        parent = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
        for path in directory.glob("*.pem"):
            if not re.fullmatch(r"[0-9a-f]{32}", path.stem):
                continue
            try:
                pem = path.read_text()
                certificate = x509.load_pem_x509_certificate(pem.encode())
                if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    continue
                certificate.verify_directly_issued_by(parent)
            except (OSError, ValueError, InvalidSignature, x509.ExtensionNotFound):
                continue
            connection.execute(
                "INSERT OR IGNORE INTO certificates VALUES (?, ?, ?)",
                (directory.name, path.stem, pem),
            )
        connection.execute("INSERT INTO imported VALUES (?)", (directory.name,))

    def page(self, directory: Path, after: str) -> tuple[list[str], str | None]:
        """Seek into a B-tree and fetch at most one page plus a continuation row."""
        with self.connection() as connection:
            self._import_legacy(connection, directory)
            rows = connection.execute(
                "SELECT id, pem FROM certificates WHERE authority=? AND id>? ORDER BY id LIMIT 51",
                (directory.name, after),
            ).fetchall()
        return [row[1] for row in rows[:50]], rows[49][0] if len(rows) > 50 else None
