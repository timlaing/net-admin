"""Explicit offline acknowledgement of a signing attempt proven not to have issued."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.inventory import PENDING_DIRECTORY
from netadmin.ca_runtime.store import AuthorityStore, durable, identifier

STATE_DIRECTORY = Path("/state")


def _flush_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def clear_failed_signing(store: AuthorityStore, authority_id: str, operation_id: str) -> None:
    """Keep an audit copy, then permit retry after the operator's external verification."""
    directory = store.directory(identifier(authority_id))
    operation_id = identifier(operation_id)
    record = store.root / "operations" / (operation_id + ".json")
    with store.lock():
        previous = json.loads(record.read_text())
        if previous.get("state") != "attempted":
            raise CAInputError("Only an uncertain attempted operation can be cleared")
        if previous.get("authority_id") != authority_id or previous.get("action") != "issue":
            raise CAInputError("Operation is not a signing attempt for this authority")
        if (directory / (operation_id + ".pem")).exists():
            raise CAInputError("Signing output exists; reconcile the certificate instead")
        with store.inventory.connection() as connection:
            if connection.execute(
                "SELECT 1 FROM certificates WHERE authority=? AND id=?",
                (authority_id, operation_id),
            ).fetchone():
                raise CAInputError("Certificate is already indexed; do not retry signing")
        archive = store.root / "reconciled"
        archive.mkdir(exist_ok=True, mode=0o700)
        target = archive / (operation_id + ".json")
        if target.exists():
            target = archive / (operation_id + "-" + uuid.uuid4().hex + ".json")
        durable(
            target,
            json.dumps(
                {
                    **previous,
                    "authority_id": authority_id,
                    "resolution": "operator-confirmed-no-issuance",
                }
            ).encode(),
        )
        _flush_directory(store.root)
        pending = directory / PENDING_DIRECTORY
        if pending.is_dir():
            (pending / operation_id).unlink(missing_ok=True)
            _flush_directory(pending)
        # Clear the retry guard last. Interrupted acknowledgement can be repeated.
        record.unlink()
        _flush_directory(record.parent)


def main() -> None:
    """Require explicit confirmation; never infer non-issuance from a CLI failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--confirm-no-certificate-issued", action="store_true", required=True)
    args = parser.parse_args()
    if not (STATE_DIRECTORY / "manifest.json").is_file():
        parser.error("Existing CA state is required at /state")
    store = AuthorityStore(STATE_DIRECTORY)
    try:
        clear_failed_signing(store, args.authority, args.operation)
    finally:
        store.inventory.close()


if __name__ == "__main__":
    main()
