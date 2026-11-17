"""Archive format, bounded capture, publication, cleanup and credential-file regressions."""

import errno
import os
import stat
import tarfile
from pathlib import Path

import pytest

from netadmin.operations import backup, paths
from netadmin.operations.errors import OperationInputError
from tests.test_operations_backup import PASSWORD, archive, boundaries  # noqa: F401


@pytest.fixture
def sample(archive):  # noqa: F811
    return archive


def test_new_archive_format_and_legacy_recovery(sample, tmp_path):
    _root, encrypted = sample
    assert encrypted.read_bytes().startswith(backup.MAGIC)
    plaintext = backup.contents(encrypted, PASSWORD)
    salt = b"0123456789abcdef"
    legacy = tmp_path / "legacy.enc"
    legacy.write_bytes(
        backup.LEGACY_MAGIC + salt + backup._cipher(PASSWORD, salt, legacy=True).encrypt(plaintext)
    )
    assert backup.verify(legacy, PASSWORD) == backup.verify(encrypted, PASSWORD)
    target = tmp_path / "legacy-restore"
    backup.restore(legacy, PASSWORD, target)
    assert (target / "ca/state").read_bytes() == b"synthetic-ca"


def test_known_format_uses_fixed_scrypt_cost(monkeypatch):
    calls = []

    class Derivation:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def derive(self, _password):
            return b"x" * 32

    monkeypatch.setattr(backup, "Scrypt", Derivation)
    backup._cipher(PASSWORD, b"s" * 16)
    backup._cipher(PASSWORD, b"s" * 16, legacy=True)
    assert calls[0]["n"] == 2**17
    assert calls[1]["n"] == 2**15
    assert all(call["r"] == 8 and call["p"] == 1 for call in calls)


def test_format_downgrade_cannot_authenticate_new_archive(sample):
    _root, encrypted = sample
    data = encrypted.read_bytes()
    encrypted.write_bytes(backup.LEGACY_MAGIC + data[len(backup.MAGIC) :])
    with pytest.raises(OperationInputError, match="authentication"):
        backup.verify(encrypted, PASSWORD)


def test_selection_stops_without_exhausting_large_tree(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    root = tmp_path / "deployment"
    root.mkdir()
    discovered = []

    def descendants():
        for index in range(100):
            discovered.append(index)
            yield SimpleNamespace(path=str(root / str(index)), is_dir=lambda **_kwargs: False)

    monkeypatch.setattr(backup.os, "scandir", lambda _path: nullcontext(descendants()))
    monkeypatch.setattr(backup, "MAX_FILES", 3)
    with pytest.raises(OperationInputError, match="too large"):
        backup._selection(root, ["."])
    assert discovered == [0, 1, 2]


def test_selection_deduplicates_overlapping_includes(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    (root / "config").mkdir(parents=True)
    child = root / "config/state"
    child.touch()
    monkeypatch.setattr(backup, "MAX_FILES", 2)
    assert backup._selection(root, ["config", "config/state"]) == {root / "config", child}


@pytest.mark.parametrize("phase", ["write", "file-sync", "directory-sync"])
def test_failed_publication_leaves_no_final_or_temporary_archive(tmp_path, monkeypatch, phase):
    output = tmp_path / "snapshot.enc"
    fsync = os.fsync

    def synchronize(descriptor):
        directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
        if (phase == "directory-sync") == directory:
            raise OSError(errno.ENOSPC, "synthetic storage failure")
        fsync(descriptor)

    if phase == "write":

        def failure(descriptor, *_args, **_kwargs):
            os.write(descriptor, b"partial")
            raise OSError(errno.ENOSPC, "synthetic write failure")

        monkeypatch.setattr(backup.os, "fdopen", failure)
    else:
        monkeypatch.setattr(backup.os, "fsync", synchronize)
    with pytest.raises(OSError):
        backup._publish_archive(output, b"synthetic-encrypted-payload")
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []
    monkeypatch.undo()
    backup._publish_archive(output, b"complete")
    assert output.read_bytes() == b"complete"


def test_publication_is_private_durable_and_never_overwrites(tmp_path, monkeypatch):
    output = tmp_path / "snapshot.enc"
    fsync = os.fsync
    syncs = []

    def synchronize(descriptor):
        syncs.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
        fsync(descriptor)

    monkeypatch.setattr(backup.os, "fsync", synchronize)
    backup._publish_archive(output, b"complete")
    assert syncs == [False, True]
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        backup._publish_archive(output, b"replacement")
    assert output.read_bytes() == b"complete"
    assert list(tmp_path.iterdir()) == [output]


def test_publication_cleanup_does_not_remove_replacement_file(tmp_path, monkeypatch):
    output = tmp_path / "snapshot.enc"
    fsync = os.fsync

    def synchronize(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            output.unlink()
            output.write_bytes(b"external replacement")
            raise OSError("synthetic directory synchronization failure")
        fsync(descriptor)

    monkeypatch.setattr(backup.os, "fsync", synchronize)
    with pytest.raises(OSError):
        backup._publish_archive(output, b"complete")
    assert output.read_bytes() == b"external replacement"


@pytest.mark.parametrize("failure", ["extract", "permissions"])
def test_failed_restore_removes_owned_partial_tree_and_can_retry(
    sample, tmp_path, monkeypatch, failure
):
    _root, encrypted = sample
    target = tmp_path / "restore"
    if failure == "extract":
        extract = tarfile.TarFile.extractfile
        calls = 0

        def missing_member(tar, member):
            nonlocal calls
            calls += 1
            return None if calls == 5 else extract(tar, member)

        monkeypatch.setattr(tarfile.TarFile, "extractfile", missing_member)
        error = ValueError
    else:
        chmod = os.fchmod
        failed = False

        def denied(descriptor, *args):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("synthetic permission failure")
            return chmod(descriptor, *args)

        monkeypatch.setattr(backup.os, "fchmod", denied)
        error = OSError
    with pytest.raises(error):
        backup.restore(encrypted, PASSWORD, target)
    assert not target.exists()
    if failure == "extract":
        monkeypatch.setattr(tarfile.TarFile, "extractfile", extract)
    else:
        monkeypatch.setattr(backup.os, "fchmod", chmod)
    backup.restore(encrypted, PASSWORD, target)
    assert (target / "ca/state").read_bytes() == b"synthetic-ca"


def test_restore_cleanup_does_not_follow_symlinks(sample, tmp_path, monkeypatch):
    _root, encrypted = sample
    target = tmp_path / "restore"
    outside = tmp_path / "unrelated"
    outside.mkdir()
    marker = outside / "retained"
    marker.write_bytes(b"protected")

    def failure(_data, destination):
        os.mkdir("owned", dir_fd=destination)
        owned = os.open("owned", os.O_RDONLY | os.O_DIRECTORY, dir_fd=destination)
        try:
            descriptor = os.open("state", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=owned)
            try:
                os.write(descriptor, b"synthetic state")
            finally:
                os.close(descriptor)
        finally:
            os.close(owned)
        os.symlink(outside, "link", dir_fd=destination, target_is_directory=True)
        raise OSError("synthetic failure")

    monkeypatch.setattr(backup, "_restore_members", failure)
    with pytest.raises(OSError):
        backup.restore(encrypted, PASSWORD, target)
    assert not target.exists()
    assert marker.read_bytes() == b"protected"


def test_restore_cleanup_preserves_replaced_target(sample, tmp_path, monkeypatch):
    _root, encrypted = sample
    target = tmp_path / "restore"

    def failure(_data, _destination):
        target.rename(tmp_path / "owned-partial")
        target.mkdir()
        (target / "protected").write_bytes(b"external replacement")
        raise OSError("synthetic failure")

    monkeypatch.setattr(backup, "_restore_members", failure)
    with pytest.raises(OSError):
        backup.restore(encrypted, PASSWORD, target)
    assert (target / "protected").read_bytes() == b"external replacement"


@pytest.mark.parametrize("kind", ["fifo", "foreign-owner", "oversized", "short"])
def test_passphrase_requires_private_owned_bounded_regular_file(tmp_path, monkeypatch, kind):
    path = tmp_path / "password"
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(
            b"x" * (4097 if kind == "oversized" else 3)
            if kind in {"oversized", "short"}
            else PASSWORD
        )
        path.chmod(0o600)
    if kind == "foreign-owner":
        owner = os.geteuid()
        monkeypatch.setattr(backup.os, "geteuid", lambda: owner + 1)
    with pytest.raises(OperationInputError):
        backup.password_file(path)


def test_passphrase_symlink_is_refused(tmp_path):
    original = tmp_path / "regular"
    original.write_bytes(PASSWORD)
    original.chmod(0o600)
    path = tmp_path / "password"
    path.symlink_to(original)
    with pytest.raises(OSError):
        backup.password_file(path)


def test_passphrase_reads_validated_descriptor_despite_path_swap(tmp_path, monkeypatch):
    path = tmp_path / "password"
    path.write_bytes(PASSWORD + b"\r\n")
    path.chmod(0o600)
    fstat = os.fstat
    opened = []

    def inspect(descriptor):
        info = fstat(descriptor)
        opened.append(descriptor)
        path.rename(tmp_path / "original-password")
        path.write_bytes(b"known-replacement-password")
        path.chmod(0o600)
        return info

    monkeypatch.setattr(backup.os, "fstat", inspect)
    assert backup.password_file(path) == PASSWORD
    with pytest.raises(OSError):
        fstat(opened[0])


@pytest.mark.parametrize(
    "action,extra,message",
    [
        ("create", [], "--root is required"),
        ("restore", [], "--target must name a new directory"),
        ("create", ["--root", "deployment"], "confirm --quiesced"),
    ],
)
def test_cli_known_validation_is_actionable(tmp_path, monkeypatch, capsys, action, extra, message):
    monkeypatch.setattr(backup, "password_file", lambda _path: PASSWORD)
    monkeypatch.setattr(
        "sys.argv",
        [
            "backup",
            action,
            "--archive",
            str(tmp_path / "snapshot.enc"),
            "--password-file",
            str(tmp_path / "password"),
            *extra,
        ],
    )
    with pytest.raises(SystemExit):
        backup.main()
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "exception",
    [ValueError("synthetic-private-diagnostic"), OSError("synthetic-private-diagnostic")],
)
def test_cli_unexpected_diagnostics_stay_redacted(tmp_path, monkeypatch, capsys, exception):
    monkeypatch.setattr(backup, "password_file", lambda _path: PASSWORD)

    def failure(*_args):
        raise exception

    monkeypatch.setattr(backup, "verify", failure)
    monkeypatch.setattr(
        "sys.argv",
        [
            "backup",
            "verify",
            "--archive",
            str(tmp_path / "snapshot.enc"),
            "--password-file",
            str(tmp_path / "password"),
        ],
    )
    with pytest.raises(SystemExit):
        backup.main()
    assert "synthetic-private-diagnostic" not in capsys.readouterr().err


def test_unknown_validation_code_cannot_echo_private_text():
    assert (
        "synthetic-private-diagnostic"
        not in OperationInputError("synthetic-private-diagnostic").public_message()
    )


def test_selection_ignores_unrelated_descendants(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    (root / "logs/deep/cache").mkdir(parents=True)
    (root / "ca").mkdir()
    target = root / "ca/state"
    target.touch()

    def unexpected(*_args):
        pytest.fail("Root-wide recursive traversal is forbidden")

    monkeypatch.setattr(Path, "rglob", unexpected)
    assert paths.existing(root, "ca/state") == target


def test_selection_rejects_intermediate_symlink_and_non_directory(tmp_path):
    root = tmp_path / "deployment"
    (root / "ca").mkdir(parents=True)
    (root / "ca/state").touch()
    (root / "alias").symlink_to(root / "ca", target_is_directory=True)
    for selected in ("alias/state", "missing/state", "ca/state/child"):
        with pytest.raises(OperationInputError):
            paths.existing(root, selected)
