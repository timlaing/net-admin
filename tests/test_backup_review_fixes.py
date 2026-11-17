"""Regression tests for CodeRabbit backup review findings on PR64.

Covers: enumeration-error propagation in tree selection, root-member
exclusion from archives, descriptor-relative restore writes, and sticky-bit
preservation on restored directory modes.
"""

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

from netadmin.operations import backup, paths


@pytest.fixture
def backup_env(tmp_path, monkeypatch):
    """Configure the paths environment for backup operations."""
    root = tmp_path / "root"
    root.mkdir()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    restore_dir = tmp_path / "restore"
    restore_dir.mkdir()
    pw_file = tmp_path / "recovery.pass"
    pw_file.write_bytes(b"0123456789abcdef0123456789abcdef")
    os.chmod(pw_file, 0o600)
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(root))
    monkeypatch.setenv("NETADMIN_BACKUP_DIRECTORY", str(backup_dir))
    monkeypatch.setenv("NETADMIN_RESTORE_DIRECTORY", str(restore_dir))
    monkeypatch.setenv("NETADMIN_RECOVERY_PASSWORD_FILE", str(pw_file))
    return tmp_path


@pytest.mark.skipif(os.geteuid() == 0, reason="Root bypasses enumeration permission bits")
def test_iter_tree_propagates_enumeration_errors(tmp_path):
    """_iter_tree must propagate directory-enumeration errors (not silence them)."""
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "child").mkdir()
    os.chmod(subdir, 0o000)
    try:
        with pytest.raises(OSError):
            list(backup._iter_tree(subdir))
    finally:
        os.chmod(subdir, 0o755)  # noqa: S103 -- test cleanup restores permissions after chmod 0o000


@pytest.mark.skipif(os.geteuid() == 0, reason="Root bypasses enumeration permission bits")
def test_selection_propagates_enumeration_errors(backup_env, tmp_path):
    """Selecting a tree whose subdirectory cannot be listed must fail."""
    root = Path(paths.configured("NETADMIN_OPERATIONS_ROOT"))
    private = root / "private"
    private.mkdir()
    (private / "state").write_text("data")
    os.chmod(private, 0o000)
    try:
        with pytest.raises(OSError):
            backup._selection(root, ["private"])
    finally:
        os.chmod(private, 0o755)  # noqa: S103 -- test cleanup restores permissions after chmod 0o000


def test_root_member_excluded_from_archive(backup_env, tmp_path):
    """Selecting the root ('') must not archive the root member itself."""
    root = Path(paths.configured("NETADMIN_OPERATIONS_ROOT"))
    backup_dir = Path(paths.configured("NETADMIN_BACKUP_DIRECTORY"))
    (root / "config").mkdir()
    (root / "config" / "settings.json").write_text("{}")
    archive = backup_dir / "archive.enc"
    password = backup.password_file(tmp_path / "recovery.pass")
    backup.create(root, [""], archive, password, quiesced=True)
    data = backup.verify(archive, password)
    assert data["files"] == 2
    contents = backup.contents(archive, password)
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:") as tar:
        names = {m.name for m in tar.getmembers()}
    assert "" not in names
    assert "." not in names
    assert "config" in names
    assert "config/settings.json" in names


def test_sticky_bit_preserved_on_restored_directory(backup_env, tmp_path):
    """A directory captured with mode 01777 is restored with the sticky bit."""
    root = Path(paths.configured("NETADMIN_OPERATIONS_ROOT"))
    backup_dir = Path(paths.configured("NETADMIN_BACKUP_DIRECTORY"))
    shared = root / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)  # noqa: S103 -- sticky-bit directory for mode round-trip regression
    archive = backup_dir / "archive.enc"
    password = backup.password_file(tmp_path / "recovery.pass")
    backup.create(root, ["shared"], archive, password, quiesced=True)
    restore_dir = Path(paths.configured("NETADMIN_RESTORE_DIRECTORY"))
    target = restore_dir / "restore-target"
    backup.restore(archive, password, target)
    restored = target / "shared"
    mode = stat.S_IMODE(restored.lstat().st_mode)
    assert mode & stat.S_ISVTX, f"sticky bit lost: mode {oct(mode)}"
    assert not (mode & stat.S_ISUID), f"setuid should be excluded: mode {oct(mode)}"
    assert not (mode & stat.S_ISGID), f"setgid should be excluded: mode {oct(mode)}"
