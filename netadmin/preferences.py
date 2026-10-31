"""Atomic, shell-safe persistence for the app's environment configuration."""

from __future__ import annotations

import os
import re
import shlex
import tempfile
from pathlib import Path


def env_path() -> Path:
    """Return the administrator-selected configuration file path."""
    candidate = Path(os.getenv("NETADMIN_ENV_FILE", "/config/netadmin.env"))
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("NETADMIN_ENV_FILE must be absolute and free of '..'")
    return candidate


def read_env_file() -> dict[str, str]:
    """Read literal assignments without executing shell expressions."""
    path = env_path()
    if not path.is_file():
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and re.fullmatch(r"NETADMIN_[A-Z_]+", key):
            parts = shlex.split(value, comments=True)
            if len(parts) <= 1:
                result[key] = parts[0] if parts else ""
    return result


def write_env_file(values: dict[str, str]) -> None:
    """Merge only supplied keys, preserving other settings and quoting literals.

    The file is sourced by the app entrypoint, so quoting is part of the write
    boundary. A private temporary file avoids exposing secrets before chmod.
    """
    if any(not re.fullmatch(r"NETADMIN_[A-Z_]+", key) for key in values):
        raise ValueError("Only NETADMIN environment keys can be saved")
    if any("\n" in value or "\r" in value or "\x00" in value for value in values.values()):
        raise ValueError("Configuration values must be single-line text")
    path = env_path()
    existing = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    lines = [line for line in existing if line.partition("=")[0].strip() not in values]
    # Quote shell metacharacters and empty strings; saved blanks override defaults.
    lines.extend(f"{key}={shlex.quote(value)}" for key, value in values.items())
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o640)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
