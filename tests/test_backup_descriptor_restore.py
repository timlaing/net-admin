"""Real traversal failures and descriptor-bound recovery must fail closed."""

import io
import os
import stat
import tarfile

import pytest

from netadmin.operations import backup
from netadmin.operations.errors import OperationInputError
from tests.test_operations_backup import PASSWORD, archive, boundaries  # noqa: F401


@pytest.fixture
def sample(archive):  # noqa: F811
    return archive


@pytest.mark.skipif(os.geteuid() == 0, reason="Root bypasses normal enumeration permission bits")
def test_real_unlistable_directory_aborts_capture_before_publication(tmp_path):
    root = tmp_path / "deployment"
    private = root / "config/private"
    private.mkdir(parents=True)
    (private / "state").write_bytes(b"synthetic-private-state")
    private.chmod(0o100)  # Traversable, but unreadable: rglob previously silently skipped it.
    output = tmp_path / "snapshot.enc"
    try:
        with pytest.raises(PermissionError):
            backup.create(root, ["config"], output, PASSWORD, quiesced=True)
        assert not output.exists()
    finally:
        private.chmod(0o700)


@pytest.mark.parametrize("selected", [".", ""])
def test_whole_root_selection_omits_root_member_and_preserves_private_target(tmp_path, selected):
    root = tmp_path / "deployment"
    root.mkdir(mode=0o755)
    (root / "config").mkdir()
    (root / "config/state").write_bytes(b"synthetic")
    output = tmp_path / "snapshot.enc"
    backup.create(root, [selected], output, PASSWORD, quiesced=True)
    data = backup.contents(output, PASSWORD)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        assert tar.getnames() == ["config", "config/state"]
    target = tmp_path / "restore"
    backup.restore(output, PASSWORD, target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert (target / "config/state").read_bytes() == b"synthetic"


def test_root_archive_member_still_fails_validation():
    member = tarfile.TarInfo(".")
    member.type = tarfile.DIRTYPE
    with pytest.raises(OperationInputError):
        backup._validate_members([member])


def test_restore_never_writes_or_changes_metadata_through_replaced_target(
    sample, tmp_path, monkeypatch
):
    _root, encrypted = sample
    target = tmp_path / "restore"
    original = tmp_path / "original-owned"
    outside = tmp_path / "unrelated"
    outside.mkdir(mode=0o755)
    sentinel = outside / "protected"
    sentinel.write_bytes(b"retained")
    mode = stat.S_IMODE(outside.stat().st_mode)
    restore_members = backup._restore_members

    def replace_target(data, descriptor):
        target.rename(original)
        target.symlink_to(outside, target_is_directory=True)
        restore_members(data, descriptor)
        # Data and metadata changes stay on the retained original object.
        assert (original / "ca/state").read_bytes() == b"synthetic-ca"
        assert list(outside.iterdir()) == [sentinel]

    monkeypatch.setattr(backup, "_restore_members", replace_target)
    with pytest.raises(OperationInputError, match="target changed"):
        backup.restore(encrypted, PASSWORD, target)
    assert sentinel.read_bytes() == b"retained"
    assert stat.S_IMODE(outside.stat().st_mode) == mode
    assert target.is_symlink()
    assert list(outside.iterdir()) == [sentinel]


def test_restore_refuses_intermediate_member_symlink(sample, tmp_path, monkeypatch):
    _root, encrypted = sample
    target = tmp_path / "restore"
    outside = tmp_path / "unrelated"
    outside.mkdir()
    sentinel = outside / "protected"
    sentinel.touch()
    restore_members = backup._restore_members

    def inject_link(data, descriptor):
        os.symlink(outside, "ca", dir_fd=descriptor, target_is_directory=True)
        restore_members(data, descriptor)

    monkeypatch.setattr(backup, "_restore_members", inject_link)
    with pytest.raises(OSError):
        backup.restore(encrypted, PASSWORD, target)
    assert list(outside.iterdir()) == [sentinel]
    assert not target.exists()


def test_restore_rejects_untrusted_writable_parent_before_creating_target(sample, tmp_path):
    _root, encrypted = sample
    target = tmp_path / "restore"
    before = stat.S_IMODE(tmp_path.stat().st_mode)
    try:
        tmp_path.chmod(0o777)
        with pytest.raises(OperationInputError, match="operator-owned"):
            backup.restore(encrypted, PASSWORD, target)
        assert not target.exists()
    finally:
        tmp_path.chmod(before)


def test_restore_preserves_sticky_but_not_setuid_setgid(tmp_path):
    root = tmp_path / "deployment"
    root.mkdir()
    shared = root / "shared"
    shared.mkdir()
    shared.chmod(0o1777)
    file = shared / "state"
    file.write_bytes(b"synthetic")
    file.chmod(0o6755)
    output = tmp_path / "snapshot.enc"
    backup.create(root, ["shared"], output, PASSWORD, quiesced=True)
    target = tmp_path / "restore"
    backup.restore(output, PASSWORD, target)
    assert stat.S_IMODE((target / "shared").stat().st_mode) == 0o1777
    assert stat.S_IMODE((target / "shared/state").stat().st_mode) == 0o755


def test_restoration_uses_the_same_authenticated_bytes_that_were_verified(
    sample, tmp_path, monkeypatch
):
    _root, encrypted = sample
    contents = backup.contents
    calls = []

    def snapshot(*args):
        calls.append("read")
        data = contents(*args)
        encrypted.write_bytes(b"changed after authenticated read")
        return data

    monkeypatch.setattr(backup, "contents", snapshot)
    target = tmp_path / "restore"
    backup.restore(encrypted, PASSWORD, target)
    assert calls == ["read"]
    assert (target / "ca/state").read_bytes() == b"synthetic-ca"
