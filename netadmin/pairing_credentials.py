"""Retire only app-owned paired identities after their in-flight requests finish."""

from __future__ import annotations

import contextlib
import fcntl
import re
import shutil
from pathlib import Path
from typing import cast

from flask import current_app, g

from netadmin.config import Settings
from netadmin.preferences import env_path, read_env_file

MANAGED = ".managed"
RETIRED = ".retired"
DIRECTORY_PATTERN = r"paired-[0-9a-f]{32}"


def directories_for(settings: Settings) -> set[Path]:
    """Recognize only app-owned credential directories referenced by active TLS files."""
    candidates = {
        value.parent
        for value in (settings.agent_ca, settings.agent_cert, settings.agent_key)
        if value is not None
    }
    return {
        path
        for path in candidates
        if path.parent == env_path().parent / "pki"
        and re.fullmatch(DIRECTORY_PATTERN, path.name)
        and not path.is_symlink()
        and (path / MANAGED).is_file()
    }


def environment_uses(path: Path) -> bool:
    """Fail closed if the committed file cannot be inspected after an interrupted write."""
    try:
        saved = read_env_file()
    except (OSError, ValueError):
        return True
    return any(
        value and Path(value).parent == path
        for field in ("CA", "CERT", "KEY")
        for value in [saved.get(f"NETADMIN_AGENT_{field}", "")]
    )


def lease(settings: Settings) -> contextlib.ExitStack | None:
    """Hold shared locks while a request could still open any part of an old identity."""
    paths = directories_for(settings)
    if not paths:
        return None
    handles = contextlib.ExitStack()
    try:
        for path in sorted(paths):
            handle = handles.enter_context((path / MANAGED).open("rb"))
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
    except OSError:
        handles.close()
        raise
    return handles


def retire(previous: Settings, current: Settings) -> None:
    """Mark superseded managed material only after active connections have changed."""
    for old in directories_for(previous) - directories_for(current):
        (old / RETIRED).touch(mode=0o600)


def collect(settings: Settings) -> None:
    """Delete retired sets only when neither active/persisted settings nor readers use them."""
    active = directories_for(settings)
    for marker in (env_path().parent / "pki").glob(f"paired-*/{RETIRED}"):
        path = marker.parent
        if (
            not re.fullmatch(DIRECTORY_PATTERN, path.name)
            or path in active
            or path.is_symlink()
            or environment_uses(path)
        ):
            continue
        with contextlib.suppress(OSError), (path / MANAGED).open("rb") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            shutil.rmtree(path)


def begin_request() -> None:
    """Snapshot credential ownership before request handlers can replace connections."""
    settings = cast(Settings, current_app.extensions["netadmin_settings"])
    g.pairing_lease = None
    with contextlib.suppress(OSError, ValueError):
        g.pairing_lease = lease(settings)


def end_request(_error: BaseException | None) -> None:
    """Release readers before attempting deferred credential cleanup."""
    handle = g.pop("pairing_lease", None)
    if handle is not None:
        handle.close()
    with contextlib.suppress(OSError, ValueError):
        collect(cast(Settings, current_app.extensions["netadmin_settings"]))
