"""Operator-configured filesystem boundaries cannot be widened by CLI arguments."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PurePosixPath

from netadmin.operations.errors import OperationInputError

FORBIDDEN = {".ssh", ".aws", ".gnupg", ".kube", ".git", ".docker", ".venv"}


def configured(name: str) -> Path:
    """Trust a separately installed operator setting, never a supplied plan/CLI path."""
    if name not in os.environ:
        raise OperationInputError("boundary_missing")
    value = Path(os.environ[name])
    if not value.is_absolute() or ".." in value.parts or value == Path("/"):
        raise OperationInputError("boundary_invalid")
    return value


def exact(requested: Path, setting: str) -> Path:
    """Return the configured path, not the original argument, after exact lexical matching."""
    trusted = configured(setting)
    if ".." in requested.parts or requested.absolute() != trusted:
        raise OperationInputError("boundary_mismatch")
    return trusted


def relative(name: str) -> PurePosixPath:
    """Reject traversal and unrelated credential stores before selecting tree entries."""
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or "\\" in name
        or set(path.parts) & FORBIDDEN
    ):
        raise OperationInputError("relative_unsafe")
    return path


def existing(root: Path, name: str) -> Path:
    """Walk only selected parents using enumerated entries, never root-wide recursion."""
    if name in {"", "."}:
        return root
    current = root
    for part in relative(name).parts:
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise OperationInputError("selection_missing")
        with os.scandir(current) as entries:
            candidate = next((Path(entry.path) for entry in entries if entry.name == part), None)
        if candidate is None:
            raise OperationInputError("selection_missing")
        if stat.S_ISLNK(candidate.lstat().st_mode):
            raise OperationInputError("selection_symlink")
        current = candidate
    return current


def location(requested: Path, setting: str) -> Path:
    """Reconstruct a safe basename beneath a configured destination directory."""
    root = configured(setting)
    name = re.sub(r"[^A-Za-z0-9_.-]", "", requested.name)
    if (
        name != requested.name
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", name)
        or ".." in requested.parts
        or requested.parent.absolute() != root
    ):
        raise OperationInputError("destination_invalid")
    return root / name
