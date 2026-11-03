"""Explicit offline acknowledgement of a signing attempt proven not to have issued."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.inventory import PENDING_DIRECTORY
from netadmin.ca_runtime.store import AuthorityStore, durable, identifier


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
        if not (directory / (operation_id + ".csr")).is_file():
            raise CAInputError("No signing request exists for this authority and operation")
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
        durable(
            archive / (operation_id + ".json"),
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
        (pending / operation_id).unlink(missing_ok=True)
        _flush_directory(pending)
        # Clear the retry guard last. Interrupted acknowledgement can be repeated.
        record.unlink()
        _flush_directory(record.parent)


def main() -> None:
    """Require explicit confirmation; never infer non-issuance from a CLI failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/state"))
    parser.add_argument("--authority", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--confirm-no-certificate-issued", action="store_true", required=True)
    args = parser.parse_args()
    store = AuthorityStore(args.state)
    try:
        clear_failed_signing(store, args.authority, args.operation)
    finally:
        store.inventory.close()


if __name__ == "__main__":
    main()
