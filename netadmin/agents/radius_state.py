"""Private, durable RADIUS rollback journals and cooperative file locks."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from netadmin.agents.common import ConfigurationChanged, validated_transaction


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Lock the entire read-modify-validate-write operation across agent workers."""
    if path.is_symlink():
        raise ValueError("Unsafe lock file")
    with path.open("a", encoding="ascii") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _sync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        candidate.chmod(mode)
        os.replace(candidate, path)
        _sync(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def _clear(path: Path) -> None:
    path.unlink(missing_ok=True)
    _sync(path.parent)


def _snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "contents": None}
    metadata = path.stat()
    return {
        "path": str(path),
        "contents": base64.b64encode(path.read_bytes()).decode("ascii"),
        "mode": metadata.st_mode & 0o777,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def recover(journal: Path, allowed: set[Path], activate: Callable[[], None]) -> None:
    """Restore an interrupted transaction before accepting new requests."""
    if not journal.exists():
        return
    if os.getenv("NETADMIN_AGENT_READ_ONLY", "false") == "true":
        raise RuntimeError("Pending RADIUS recovery requires a writable agent")
    if journal.is_symlink() or journal.stat().st_mode & 0o077:
        raise ValueError("Unsafe transaction journal")
    payload = json.loads(journal.read_bytes())
    entries = payload["entries"]
    # The journal is private, but its contents cannot grant additional write paths.
    paths = [Path(entry["path"]) for entry in entries]
    if not paths or len(set(paths)) != len(paths) or not set(paths) <= allowed:
        raise ValueError("Unsupported recovery paths")
    if any(path.resolve() != path for path in paths):
        raise ValueError("Recovery paths changed")
    if payload["state"] == "prepared":
        for path, entry in zip(paths, entries, strict=True):
            _restore(path, entry)
        activate()
    elif payload["state"] != "committed":
        raise ValueError("Unsupported recovery state")
    _clear(journal)


def _restore(path: Path, entry: dict[str, Any]) -> None:
    if entry["contents"] is None:
        path.unlink(missing_ok=True)
        _sync(path.parent)
        return
    _write(path, base64.b64decode(entry["contents"], validate=True), entry["mode"])
    os.chown(path, entry["uid"], entry["gid"])
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def transaction(
    changes: dict[Path, str],
    validate: Callable[[], None],
    reload_command: list[str],
    *,
    journal: Path,
    rollback: Callable[[], None],
    expected: dict[Path, bytes | None] | None = None,
) -> None:
    """Persist originals before replacement and a commit marker after activation."""
    if journal.exists():
        raise RuntimeError("Recover the previous transaction before writing")
    changes = {path.resolve(): value for path, value in changes.items()}
    payload = {"state": "prepared", "entries": [_snapshot(path) for path in changes]}
    _write(journal, json.dumps(payload).encode())
    try:
        validated_transaction(
            changes,
            validate,
            reload_command,
            allowed_roots=tuple(path.parent for path in changes),
            expected_originals=expected,
        )
    except ConfigurationChanged:
        _clear(journal)  # No replacement happened: retain the external editor's changes.
        raise
    except Exception:
        recover(journal, set(changes), rollback)
        raise
    for path in changes:
        _sync(path.parent)
    payload["state"] = "committed"
    _write(journal, json.dumps(payload).encode())
    _clear(journal)
