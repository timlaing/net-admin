"""Indexed public certificate inventory; never stores keys or configuration."""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import time
import weakref
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature

PENDING_DIRECTORY = "inventory-pending"


class _Scan(Protocol):
    def __next__(self) -> os.DirEntry[str]: ...
    def close(self) -> None:
        """Release the directory descriptor."""
        ...


def _close_scans(scans: dict[str, _Scan]) -> None:
    for scan in scans.values():
        scan.close()
    scans.clear()


class CertificateInventory:
    """Bound migration work and cursor reads independently of issuance history."""

    def __init__(self, root: Path):
        self.path = root / "certificate-inventory.sqlite"
        self.scans: dict[str, _Scan] = {}
        self.failed: set[str] = set()
        weakref.finalize(self, _close_scans, self.scans)

    def close(self) -> None:
        """Release any paused legacy-directory scans on controller shutdown."""
        _close_scans(self.scans)
        self.failed.clear()

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Close rolls back an interrupted transaction; commit only on success."""
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
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS processed "
                    "(authority TEXT, id TEXT, PRIMARY KEY(authority,id))"
                )
                yield connection
                connection.commit()
        except sqlite3.Error as error:
            raise OSError("Public certificate inventory unavailable") from error

    @staticmethod
    def prepare(directory: Path, operation_id: str) -> None:
        """Persist reconciliation intent before any external signing side effect."""
        pending = directory / PENDING_DIRECTORY
        pending.mkdir(exist_ok=True, mode=0o700)
        marker = pending / operation_id
        created = False
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            for path in (pending, directory):
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except OSError:
            if created:
                with contextlib.suppress(OSError):
                    marker.unlink(missing_ok=True)
            raise

    def record(self, directory: Path, operation_id: str, pem: str) -> None:
        """Index verified output; remove intent only after its committed row exists."""
        with self.connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?)",
                (directory.name, operation_id, pem),
            )
        with contextlib.suppress(OSError):
            (directory / PENDING_DIRECTORY / operation_id).unlink(missing_ok=True)

    def _reconcile_pending(self, connection: sqlite3.Connection, directory: Path) -> list[Path]:
        pending = directory / PENDING_DIRECTORY
        if not pending.is_dir():
            return []
        key = "pending:" + directory.name
        if key not in self.scans:
            self.scans[key] = os.scandir(pending)
        parent = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
        complete = []
        for _ in range(50):
            try:
                entry = next(self.scans[key])
            except StopIteration:
                self._reset(key)
                break
            if not re.fullmatch(r"[0-9a-f]{32}", entry.name):
                continue
            marker = Path(entry.path)
            identity = (directory.name, entry.name)
            if connection.execute(
                "SELECT 1 FROM certificates WHERE authority=? AND id=?", identity
            ).fetchone():
                complete.append(marker)
                continue
            try:
                pem = self._read_leaf(directory / (entry.name + ".pem"), parent)
            except OSError:
                continue
            if pem is not None:
                connection.execute("INSERT INTO certificates VALUES (?, ?, ?)", (*identity, pem))
                complete.append(marker)
        return complete

    def _reset(self, authority: str) -> None:
        scan = self.scans.pop(authority, None)
        if scan is not None:
            scan.close()
        self.failed.discard(authority)

    @staticmethod
    def _read_leaf(path: Path, parent: x509.Certificate) -> str | None:
        # I/O errors are deliberately not swallowed: they keep migration pending.
        try:
            pem = path.read_text()
            certificate = x509.load_pem_x509_certificate(pem.encode())
            if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return None
            certificate.verify_directly_issued_by(parent)
        except (ValueError, InvalidSignature, x509.ExtensionNotFound):
            return None
        return pem

    def _candidate(
        self,
        connection: sqlite3.Connection,
        directory: Path,
        entry: os.DirEntry[str],
        parent: x509.Certificate,
    ) -> bool:
        name = entry.name.removesuffix(".pem")
        if not entry.name.endswith(".pem") or not re.fullmatch(r"[0-9a-f]{32}", name):
            return False
        if not entry.is_file(follow_symlinks=False):
            return False
        key = (directory.name, name)
        if connection.execute("SELECT 1 FROM processed WHERE authority=? AND id=?", key).fetchone():
            return False
        try:
            pem = self._read_leaf(Path(entry.path), parent)
        except OSError:
            self.failed.add(directory.name)
            return True
        if pem is not None:
            connection.execute("INSERT OR IGNORE INTO certificates VALUES (?, ?, ?)", (*key, pem))
        connection.execute("INSERT OR IGNORE INTO processed VALUES (?, ?)", key)
        return True

    def _import_batch(self, connection: sqlite3.Connection, directory: Path) -> None:
        authority = directory.name
        if connection.execute("SELECT 1 FROM imported WHERE authority=?", (authority,)).fetchone():
            return
        if authority not in self.scans:
            self.scans[authority] = os.scandir(directory)
        parent = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
        deadline, reads = time.monotonic() + 0.5, 0
        for _ in range(1000):
            if reads >= 50 or time.monotonic() >= deadline:
                return
            try:
                entry = next(self.scans[authority])
            except StopIteration:
                complete = authority not in self.failed
                self._reset(authority)
                if complete:
                    connection.execute("INSERT INTO imported VALUES (?)", (authority,))
                return
            reads += self._candidate(connection, directory, entry, parent)

    def pending(self, directory: Path) -> bool:
        """Expose partial imports and unresolved issuance intents honestly."""
        with self.connection() as connection:
            incomplete = not bool(
                connection.execute(
                    "SELECT 1 FROM imported WHERE authority=?", (directory.name,)
                ).fetchone()
            )
        pending = directory / PENDING_DIRECTORY
        if pending.is_dir():
            with os.scandir(pending) as scan:
                return incomplete or next(scan, None) is not None
        return incomplete

    def page(self, directory: Path, after: str) -> tuple[list[str], str | None]:
        """Import one bounded batch, then fetch at most a page plus one row."""
        dirty = directory / "inventory-dirty"
        refresh = dirty.exists()
        try:
            with self.connection() as connection:
                if refresh:
                    connection.execute("DELETE FROM imported WHERE authority=?", (directory.name,))
                    self._reset(directory.name)
                completed = self._reconcile_pending(connection, directory)
                self._import_batch(connection, directory)
                rows = connection.execute(
                    "SELECT id, pem FROM certificates WHERE authority=? AND id>? "
                    "ORDER BY id LIMIT 51",
                    (directory.name, after),
                ).fetchall()
        except (OSError, ValueError):
            # Never retain a cursor advanced by a transaction that rolled back.
            self._reset(directory.name)
            self._reset("pending:" + directory.name)
            raise
        for marker in completed:
            with contextlib.suppress(OSError):
                marker.unlink(missing_ok=True)
        if refresh:
            with contextlib.suppress(OSError):
                dirty.unlink()
        return [row[1] for row in rows[:50]], rows[49][0] if len(rows) > 50 else None
