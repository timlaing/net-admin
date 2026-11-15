"""Operator-configured filesystem boundaries cannot be widened by CLI arguments."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

FORBIDDEN = {".ssh", ".aws", ".gnupg", ".kube", ".git", ".docker", ".venv"}


def configured(name: str) -> Path:
    """Trust a separately installed operator setting, never a supplied plan/CLI path."""
    if name not in os.environ:
        raise ValueError("Install the trusted operation boundary before invoking this CLI")
    value = Path(os.environ[name])
    if not value.is_absolute() or ".." in value.parts or value == Path("/"):
        raise ValueError("Operation boundary must be an absolute, dedicated path")
    return value


def exact(requested: Path, setting: str) -> Path:
    """Return the configured path, not the original argument, after exact lexical matching."""
    trusted = configured(setting)
    if ".." in requested.parts or requested.absolute() != trusted:
        raise ValueError("Argument does not match the configured operation boundary")
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
        raise ValueError("Unsafe or unrelated credential-store path")
    return path


def existing(root: Path, name: str) -> Path:
    """Select from server-enumerated paths; never probe an argument-constructed filename."""
    if name in {"", "."}:
        return root
    wanted = str(relative(name))
    for count, candidate in enumerate(root.rglob("*")):
        if count >= 100_000:
            raise ValueError("Operation tree exceeds its selection limit")
        if str(candidate.relative_to(root)) == wanted:
            if candidate.is_symlink():
                raise ValueError("Operation selection may not follow a symlink")
            return candidate
    raise ValueError("Operation selection is unavailable")


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
        raise ValueError("Destination is outside the configured operation boundary")
    return root / name
