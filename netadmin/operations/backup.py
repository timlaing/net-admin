"""Encrypted, bounded offline backups with non-destructive restore verification."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import shutil
import stat
import tarfile
from collections.abc import Generator, Iterator
from contextlib import ExitStack, closing, contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from netadmin.operations import paths
from netadmin.operations.errors import OperationInputError

MAGIC = b"NETADMIN-BACKUP-2\n"
LEGACY_MAGIC = b"NETADMIN-BACKUP-1\n"
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
            raise OperationInputError("source_changed")
        member.size = actual.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            archive.addfile(member, source)


def _cipher(password: bytes, salt: bytes, *, legacy: bool = False) -> Fernet:
    if not 16 <= len(password) <= 1024:
        raise OperationInputError("password_length")
    key = Scrypt(salt=salt, length=32, n=2**15 if legacy else 2**17, r=8, p=1).derive(password)
    return Fernet(base64.urlsafe_b64encode(key))


def _relative(name: str) -> PurePosixPath:
    return paths.relative(name)


def _selection(root: Path, includes: list[str]) -> set[Path]:
    selected: set[Path] = set()
    for name in includes:
        path = paths.existing(root, name)
        selected.add(path)
        _selection_limit(selected)
        if path.is_dir():
            with closing(_descendants(path)) as descendants:
                for child in descendants:
                    selected.add(child)
                    _selection_limit(selected)
    _selection_limit(selected)
    return selected


def _descendants(root: Path) -> Generator[Path, None, None]:
    """Enumerate selected trees without swallowing errors or following directory links."""
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                child = Path(entry.path)
                yield child
                if entry.is_dir(follow_symlinks=False):
                    pending.append(child)


def _selection_limit(selected: set[Path]) -> None:
    if not selected or len(selected) > MAX_FILES:
        raise OperationInputError("selection_limit")


def _write_tar(root: Path, includes: list[str]) -> bytes:
    data = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=data, mode="w") as archive:
        for path in sorted(_selection(root, includes)):
            if path == root:
                continue  # Never restore archive metadata onto the private target root.
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                continue
            _relative(str(path.relative_to(root)))
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise OperationInputError("source_type")
            total += info.st_size if path.is_file() else 0
            if total > MAX_BYTES:
                raise OperationInputError("capture_limit")
            _add(archive, path, root, info)
    return data.getvalue()


def create(
    root: Path, includes: list[str], output: Path, password: bytes, *, quiesced: bool
) -> None:
    """Require stopped writers; include full selected config/lease/CA trees, never sockets."""
    if not quiesced:
        raise OperationInputError("quiescence")
    root = paths.exact(root, "NETADMIN_OPERATIONS_ROOT").resolve(strict=True)
    output = paths.location(output, "NETADMIN_BACKUP_DIRECTORY")
    if output.resolve().is_relative_to(root):
        raise OperationInputError("archive_location")
    salt = os.urandom(16)
    encrypted = MAGIC + salt + _cipher(password, salt).encrypt(_write_tar(root, includes))
    _publish_archive(output, encrypted)


def _unlink_owned(name: str, directory: int, identity: os.stat_result) -> None:
    """Failure cleanup may remove only the file this operation created."""
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            os.unlink(name, dir_fd=directory)
    except OSError:
        # Preserve the original failure; private storage may need manual cleanup.
        pass


def _publish_archive(output: Path, encrypted: bytes) -> None:
    """Publish a fsynced complete file without replacing any existing final name."""
    with ExitStack() as stack:
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, directory)
        temporary = f".{output.name}.{os.urandom(8).hex()}.partial"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        stack.callback(os.close, descriptor)
        identity = os.fstat(descriptor)
        stack.callback(_unlink_owned, temporary, directory, identity)
        published = False
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(
                temporary,
                output.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            published = True
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        except BaseException:
            if published:
                _unlink_owned(output.name, directory, identity)
            raise


def contents(archive: Path, password: bytes) -> bytes:
    """Authenticate before examining paths or exposing any archived data."""
    archive = paths.location(archive, "NETADMIN_BACKUP_DIRECTORY")
    if archive.suffix != ".enc":
        raise OperationInputError("archive_extension")
    with ExitStack() as stack:
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stack.callback(os.close, descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * MAX_BYTES:
            raise OperationInputError("archive_type")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(2 * MAX_BYTES + 1)
    if len(data) > 2 * MAX_BYTES:
        raise OperationInputError("archive_limit")
    legacy = data.startswith(LEGACY_MAGIC)
    if not (data.startswith(MAGIC) or legacy) or len(data) < len(MAGIC) + 16:
        raise OperationInputError("archive_format")
    start = len(MAGIC)
    try:
        return _cipher(password, data[start : start + 16], legacy=legacy).decrypt(
            data[start + 16 :]
        )
    except InvalidToken as error:
        raise OperationInputError("authentication") from error


def _validate_members(members: list[tarfile.TarInfo]) -> None:
    if len(members) > MAX_FILES or sum(m.size for m in members) > MAX_BYTES:
        raise OperationInputError("restore_limit")
    names: set[str] = set()
    files = {str(_relative(m.name)) for m in members if m.isfile()}
    for member in members:
        name = str(_relative(member.name))
        if member.size < 0 or any(str(parent) in files for parent in PurePosixPath(name).parents):
            raise OperationInputError("member_parent")
        if name in names or not (member.isfile() or member.isdir()):
            raise OperationInputError("member_type")
        names.add(name)


def verify(archive: Path, password: bytes) -> dict[str, int]:
    """Check every member before any restore; reject duplicate/link/special entries."""
    return _verify_data(contents(archive, password))


def _verify_data(data: bytes) -> dict[str, int]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        members = tar.getmembers()
        _validate_members(members)
        for member in members:
            if member.isfile():
                handle = tar.extractfile(member)
                if handle is None or len(handle.read()) != member.size:
                    raise OperationInputError("member_incomplete")
        return {"files": len(members), "bytes": sum(m.size for m in members)}


def restore(archive: Path, password: bytes, target: Path) -> dict[str, int]:
    """Restore to a NEW private directory only, preserving modes and root-owned IDs."""
    data = contents(archive, password)
    report = _verify_data(data)
    target = paths.location(target, "NETADMIN_RESTORE_DIRECTORY")
    with ExitStack() as stack:
        parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, parent)
        parent_info = os.fstat(parent)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise OperationInputError("restore_parent")
        os.mkdir(target.name, 0o700, dir_fd=parent)
        identity = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
        own = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, own)
        if _identity(os.fstat(own)) != _identity(identity):
            raise OperationInputError("restore_changed")
        try:
            _restore_members(data, own)
            if not _target_matches(parent, target.name, own):
                raise OperationInputError("restore_changed")
        except BaseException:
            _cleanup_restore(parent, target.name, own)
            raise
    return report


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _target_matches(parent: int, name: str, own: int) -> bool:
    try:
        return _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(
            os.fstat(own)
        )
    except FileNotFoundError:
        return False


def _cleanup_restore(parent: int, name: str, own: int) -> None:
    """Remove only the new restore tree, using descriptor-relative symlink-safe cleanup."""
    if not shutil.rmtree.avoids_symlink_attacks:
        return
    try:
        os.fchmod(own, 0o700)
        with os.scandir(own) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.name, dir_fd=own)
                else:
                    os.unlink(entry.name, dir_fd=own)
        if _target_matches(parent, name, own):
            os.rmdir(name, dir_fd=parent)
    except OSError:
        # Keep failed cleanup private; documentation describes manual recovery.
        pass


@contextmanager
def _directory_descriptor(root: int, parts: tuple[str, ...], *, make_dirs: bool) -> Iterator[int]:
    """Walk each component relative to a retained root, refusing intermediate symlinks."""
    descriptor = os.dup(root)
    try:
        for part in parts:
            if make_dirs:
                with suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=descriptor)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def _restore_members(data: bytes, target: int) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        members = tar.getmembers()
        for member in members:
            _restore_member(tar, member, target)
        # Apply directories last: restoring restrictive modes early blocks children.
        for member in sorted(members, key=lambda m: len(PurePosixPath(m.name).parts), reverse=True):
            _restore_metadata(member, target)


def _restore_member(tar: tarfile.TarFile, member: tarfile.TarInfo, target: int) -> None:
    parts = _relative(member.name).parts
    if member.isdir():
        with _directory_descriptor(target, parts, make_dirs=True):
            return
    handle = tar.extractfile(member)
    if handle is None:
        raise OperationInputError("member_incomplete")
    with _directory_descriptor(target, parts[:-1], make_dirs=True) as parent, ExitStack() as stack:
        descriptor = os.open(
            parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        stack.callback(os.close, descriptor)
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(handle.read())


def _restore_metadata(member: tarfile.TarInfo, target: int) -> None:
    parts = _relative(member.name).parts
    with _directory_descriptor(target, parts[:-1], make_dirs=False) as parent, ExitStack() as stack:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if member.isdir():
            flags |= os.O_DIRECTORY
        descriptor = os.open(parts[-1], flags, dir_fd=parent)
        stack.callback(os.close, descriptor)
        mode = os.fstat(descriptor).st_mode
        valid = stat.S_ISDIR(mode) if member.isdir() else stat.S_ISREG(mode)
        if not valid:
            raise OperationInputError("member_type")
        if os.geteuid() == 0:
            os.fchown(descriptor, member.uid, member.gid)
        os.fchmod(descriptor, member.mode & 0o1777)


def password_file(path: Path) -> bytes:
    """Recovery material is supplied locally; never copied into manifests or output."""
    path = paths.exact(path, "NETADMIN_RECOVERY_PASSWORD_FILE")
    with ExitStack() as stack:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stack.callback(os.close, descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
            or info.st_size > 4096
        ):
            raise OperationInputError("password_file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(4097)
        if len(content) > 4096:
            raise OperationInputError("password_file")
        password = content.rstrip(b"\r\n")
        if not 16 <= len(password) <= 1024:
            raise OperationInputError("password_length")
        return password


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
                raise OperationInputError("root_required")
            create(args.root, args.include, args.archive, password, quiesced=args.quiesced)
            report = verify(args.archive, password)
        elif args.action == "restore":
            if args.target is None:
                raise OperationInputError("target_required")
            report = restore(args.archive, password, args.target)
        else:
            report = verify(args.archive, password)
        print(json.dumps({"verified": True, **report}))
    except OperationInputError as error:
        parser.exit(1, error.public_message() + "\n")
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Backup operation failed; private diagnostics were suppressed.\n")


if __name__ == "__main__":
    main()
