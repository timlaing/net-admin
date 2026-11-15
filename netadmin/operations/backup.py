"""Encrypted, bounded offline backups with non-destructive restore verification."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import stat
import tarfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from netadmin.operations import paths

MAGIC = b"NETADMIN-BACKUP-1\n"
MAX_BYTES = 256 * 1024 * 1024
MAX_FILES = 100_000


def _add(archive: tarfile.TarFile, path: Path, root: Path, info: os.stat_result) -> None:
    """Store hard-linked files as independent data; never follow a final symlink."""
    member = tarfile.TarInfo(str(path.relative_to(root)))
    member.mode, member.uid, member.gid, member.mtime = (
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_mtime,
    )
    if stat.S_ISDIR(info.st_mode):
        member.type = tarfile.DIRTYPE
        archive.addfile(member)
        return
    with ExitStack() as stack:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stack.callback(os.close, descriptor)
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_ino, actual.st_size) != (
            info.st_ino,
            info.st_size,
        ):
            raise ValueError("Backup source changed during capture")
        member.size = actual.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            archive.addfile(member, source)


def _cipher(password: bytes, salt: bytes) -> Fernet:
    if not 16 <= len(password) <= 1024:
        raise ValueError("Recovery passphrase must contain 16-1024 bytes")
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)
    return Fernet(base64.urlsafe_b64encode(key))


def _relative(name: str) -> PurePosixPath:
    return paths.relative(name)


def _selection(root: Path, includes: list[str]) -> set[Path]:
    selected: set[Path] = set()
    for name in includes:
        path = paths.existing(root, name)
        selected.add(path)
        if path.is_dir():
            selected.update(path.rglob("*"))
    if not selected or len(selected) > MAX_FILES:
        raise ValueError("Backup selection is empty or too large")
    return selected


def _write_tar(root: Path, includes: list[str]) -> bytes:
    data = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=data, mode="w") as archive:
        for path in sorted(_selection(root, includes)):
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                continue
            _relative(str(path.relative_to(root)))
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("Backup sources may not contain links or special files")
            total += info.st_size if path.is_file() else 0
            if total > MAX_BYTES:
                raise ValueError("Backup exceeds its safety limit; partition the selection")
            _add(archive, path, root, info)
    return data.getvalue()


def create(
    root: Path, includes: list[str], output: Path, password: bytes, *, quiesced: bool
) -> None:
    """Require stopped writers; include full selected config/lease/CA trees, never sockets."""
    if not quiesced:
        raise ValueError("Stop all writers first and confirm --quiesced")
    root = paths.exact(root, "NETADMIN_OPERATIONS_ROOT").resolve(strict=True)
    output = paths.location(output, "NETADMIN_BACKUP_DIRECTORY")
    if output.resolve().is_relative_to(root):
        raise ValueError("Store backup archives outside the source tree")
    salt = os.urandom(16)
    encrypted = MAGIC + salt + _cipher(password, salt).encrypt(_write_tar(root, includes))
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encrypted)
        handle.flush()
        os.fsync(handle.fileno())


def contents(archive: Path, password: bytes) -> bytes:
    """Authenticate before examining paths or exposing any archived data."""
    archive = paths.location(archive, "NETADMIN_BACKUP_DIRECTORY")
    if archive.suffix != ".enc":
        raise ValueError("Use an encrypted backup archive")
    with ExitStack() as stack:
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stack.callback(os.close, descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * MAX_BYTES:
            raise ValueError("Encrypted archive is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(2 * MAX_BYTES + 1)
    if len(data) > 2 * MAX_BYTES:
        raise ValueError("Encrypted archive exceeds its size limit")
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 16:
        raise ValueError("Unsupported backup format")
    start = len(MAGIC)
    try:
        return _cipher(password, data[start : start + 16]).decrypt(data[start + 16 :])
    except InvalidToken as error:
        raise ValueError("Backup authentication failed") from error


def _validate_members(members: list[tarfile.TarInfo]) -> None:
    if len(members) > MAX_FILES or sum(m.size for m in members) > MAX_BYTES:
        raise ValueError("Backup exceeds restoration limits")
    names: set[str] = set()
    files = {str(_relative(m.name)) for m in members if m.isfile()}
    for member in members:
        name = str(_relative(member.name))
        if member.size < 0 or any(str(parent) in files for parent in PurePosixPath(name).parents):
            raise ValueError("Backup member has an unsafe parent or size")
        if name in names or not (member.isfile() or member.isdir()):
            raise ValueError("Backup contains duplicate, linked or special members")
        names.add(name)


def verify(archive: Path, password: bytes) -> dict[str, int]:
    """Check every member before any restore; reject duplicate/link/special entries."""
    with tarfile.open(fileobj=io.BytesIO(contents(archive, password)), mode="r:") as tar:
        members = tar.getmembers()
        _validate_members(members)
        for member in members:
            if member.isfile():
                handle = tar.extractfile(member)
                if handle is None or len(handle.read()) != member.size:
                    raise ValueError("Backup member is incomplete")
        return {"files": len(members), "bytes": sum(m.size for m in members)}


def restore(archive: Path, password: bytes, target: Path) -> dict[str, int]:
    """Restore to a NEW private directory only, preserving modes and root-owned IDs."""
    report = verify(archive, password)
    target = paths.location(target, "NETADMIN_RESTORE_DIRECTORY")
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(contents(archive, password)), mode="r:") as tar:
        members = tar.getmembers()
        for member in members:
            path = target.joinpath(*_relative(member.name).parts)
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                handle = tar.extractfile(member)
                if handle is None:
                    raise ValueError("Backup member is incomplete")
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "wb") as destination:
                    destination.write(handle.read())
        # Apply directories last: restoring restrictive modes early blocks children.
        for member in sorted(members, key=lambda m: len(PurePosixPath(m.name).parts), reverse=True):
            path = target.joinpath(*_relative(member.name).parts)
            if os.geteuid() == 0:
                os.chown(path, member.uid, member.gid)
            path.chmod(member.mode & 0o777)
    return report


def password_file(path: Path) -> bytes:
    """Recovery material is supplied locally; never copied into manifests or output."""
    path = paths.exact(path, "NETADMIN_RECOVERY_PASSWORD_FILE")
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("Recovery passphrase file must be private (0600) and not a symlink")
    return path.read_bytes().rstrip(b"\r\n")


def main() -> None:
    """Explicit offline capture, verification or restore into a new private directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify", "restore"))
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--target", type=Path)
    parser.add_argument("--quiesced", action="store_true")
    args = parser.parse_args()
    try:
        password = password_file(args.password_file)
        report: dict[str, Any]
        if args.action == "create":
            if args.root is None:
                raise ValueError("--root is required")
            create(args.root, args.include, args.archive, password, quiesced=args.quiesced)
            report = verify(args.archive, password)
        elif args.action == "restore":
            if args.target is None:
                raise ValueError("--target must name a new directory")
            report = restore(args.archive, password, args.target)
        else:
            report = verify(args.archive, password)
        print(json.dumps({"verified": True, **report}))
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Backup operation failed; private diagnostics were suppressed.\n")


if __name__ == "__main__":
    main()
