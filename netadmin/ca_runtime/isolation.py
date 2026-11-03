"""OS ownership boundary between the lifecycle controller and native issuers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.store import AuthorityStore


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
    if not home.exists():
        home.mkdir(mode=0o770)
        home.chmod(0o770)
        os.chown(home, uid, 0)
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
