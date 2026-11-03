"""OS ownership boundary between the lifecycle controller and native issuers."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.store import AuthorityStore


def _walk_error(error: OSError) -> None:
    raise error


def _migrate_home(home: Path, uid: int) -> None:
    """Convert controller-owned local state without following links or touching vaults.

    Preflight the complete tree before mutation. Already converted paths are
    accepted so interruption can resume without granting extra capabilities.
    """
    paths = [home]
    for parent, directories, files in os.walk(home, followlinks=False, onerror=_walk_error):
        paths.extend(Path(parent) / name for name in [*directories, *files])
    for path in paths:
        info = path.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise CAInputError("Issuer ownership migration refuses links or special files")
        if info.st_uid not in {0, uid}:
            raise CAInputError(
                "Stop the issuer and migrate its non-controller-owned runtime explicitly"
            )
        mode = 0o770 if directory else 0o660
        if info.st_uid == uid and (info.st_gid != 0 or info.st_mode & 0o777 != mode):
            raise CAInputError("Issuer runtime has unexpected ownership or permissions")
    # Publish the top-level owner last; a partial conversion remains resumable.
    for path in reversed(paths):
        info = path.stat()
        if info.st_uid == 0:
            path.chmod(0o770 if stat.S_ISDIR(info.st_mode) else 0o660)
            os.chown(path, uid, 0)


def prepare(store: AuthorityStore, authority_id: str) -> dict[str, Any]:
    """Grant each Linux child only its own immutable inputs and writable home.

    Controller files remain root-owned. Issuer groups can read only the explicit
    native inputs, not metadata, root material, provisioner secrets or siblings.
    Local library/test use can omit OS isolation; the runtime image enables it.
    """
    if os.environ.get("CA_ISOLATE_ISSUERS") != "1":
        (store.directory(authority_id) / "runtime").mkdir(exist_ok=True, mode=0o700)
        return {}
    if os.geteuid() != 0:
        raise CAInputError("Issuer isolation requires the privileged lifecycle controller")
    directory = store.directory(authority_id)
    port = store.metadata(authority_id)["port"]
    if not isinstance(port, int) or not 9100 <= port <= 9115:
        raise CAInputError("Invalid issuer port identity")
    uid = 20000 + port - 9100
    for path in (store.root, store.root / "authorities", directory):
        path.chmod(0o711)
    home = directory / "runtime"
    if home.is_symlink():
        raise CAInputError("Issuer runtime must not be a symbolic link")
    if not home.exists():
        home.mkdir(mode=0o770)
        home.chmod(0o770)
        os.chown(home, uid, 0)
    elif home.stat().st_uid == 0:
        _migrate_home(home, uid)
    elif (
        home.stat().st_uid != uid or home.stat().st_gid != 0 or home.stat().st_mode & 0o777 != 0o770
    ):
        raise CAInputError("Issuer runtime directory has unexpected ownership or permissions")
    for name in ("config.json", "root.crt", "issuing-chain.pem", "ca.key", "password"):
        path = directory / name
        os.chown(path, 0, uid)
        path.chmod(0o640)
    return {"user": uid, "group": uid, "extra_groups": (), "umask": 0o077}


def environment(directory: Path) -> dict[str, str]:
    """Never pass lifecycle credentials or deployment environment to an issuer."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(directory / "runtime")}
