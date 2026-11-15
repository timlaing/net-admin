"""Backups include service state, authenticate data and never overwrite live paths."""

import os

import pytest

from netadmin.operations.backup import create, password_file, restore, verify

PASSWORD = b"synthetic-recovery-passphrase"


@pytest.fixture
def archive(tmp_path):
    root = tmp_path / "deployment"
    root.mkdir()
    for name in ("config", "leases", "ca", "transport"):
        (root / name).mkdir()
        (root / name / "state").write_bytes(b"synthetic-" + name.encode())
        (root / name / "state").chmod(0o600)
    output = tmp_path / "snapshot.enc"
    create(root, ["config", "leases", "ca", "transport"], output, PASSWORD, quiesced=True)
    return root, output


def test_encrypted_restore_preserves_state_and_permissions(archive, tmp_path):
    root, encrypted = archive
    assert b"synthetic-ca" not in encrypted.read_bytes()
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert verify(encrypted, PASSWORD)["files"] == 8
    target = tmp_path / "restore-test"
    restore(encrypted, PASSWORD, target)
    for file in root.rglob("state"):
        restored = target / file.relative_to(root)
        assert restored.read_bytes() == file.read_bytes()
        assert restored.stat().st_mode & 0o777 == 0o600


def test_restore_refuses_existing_directory(archive, tmp_path):
    root, encrypted = archive
    with pytest.raises(FileExistsError):
        restore(encrypted, PASSWORD, root)
    assert (root / "ca/state").read_bytes() == b"synthetic-ca"


@pytest.mark.parametrize("failure", ["password", "tamper"])
def test_archive_authentication_before_any_writes(archive, tmp_path, failure):
    _root, encrypted = archive
    if failure == "tamper":
        data = bytearray(encrypted.read_bytes())
        data[-20] ^= 1
        encrypted.write_bytes(data)
    target = tmp_path / "never-created"
    with pytest.raises(ValueError):
        restore(
            encrypted, PASSWORD if failure == "tamper" else b"another-synthetic-password", target
        )
    assert not target.exists()


def test_quiescence_and_safe_selection_are_required(tmp_path):
    root = tmp_path / "deployment"
    root.mkdir()
    (root / "state").write_bytes(b"synthetic")
    output = tmp_path / "snapshot.enc"
    with pytest.raises(ValueError):
        create(root, ["state"], output, PASSWORD, quiesced=False)
    for selected in ("../outside", "/absolute"):
        with pytest.raises(ValueError):
            create(root, [selected], output, PASSWORD, quiesced=True)
    (root / "link").symlink_to(root / "state")
    with pytest.raises(ValueError):
        create(root, ["link"], output, PASSWORD, quiesced=True)


def test_password_permissions_are_enforced(tmp_path):
    path = tmp_path / "password"
    path.write_bytes(PASSWORD)
    path.chmod(0o600)
    assert password_file(path) == PASSWORD
    path.chmod(0o644)
    with pytest.raises(ValueError):
        password_file(path)


def test_fifo_is_not_backed_up(tmp_path):
    root = tmp_path / "deployment"
    root.mkdir()
    os.mkfifo(root / "fifo")
    with pytest.raises(ValueError):
        create(root, ["fifo"], tmp_path / "archive.enc", PASSWORD, quiesced=True)


@pytest.mark.parametrize("action", ["create", "verify", "restore"])
def test_cli_reports_only_verification_metadata(archive, tmp_path, monkeypatch, capsys, action):
    from netadmin.operations.backup import main

    root, encrypted = archive
    password = tmp_path / "password"
    password.write_bytes(PASSWORD)
    password.chmod(0o600)
    args = ["backup", action, "--archive", str(encrypted), "--password-file", str(password)]
    if action == "create":
        args[3] = str(tmp_path / "new.enc")
        args += ["--root", str(root), "--include", "config", "--quiesced"]
    if action == "restore":
        args += ["--target", str(tmp_path / "rehearsal")]
    monkeypatch.setattr("sys.argv", args)
    main()
    assert '"verified": true' in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["traversal", "symlink", "hardlink", "duplicate", "parent"])
def test_authenticated_unsafe_archive_is_rejected_before_restore(tmp_path, kind):
    import io
    import tarfile

    from netadmin.operations.backup import MAGIC, _cipher

    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        member = tarfile.TarInfo("../escape" if kind == "traversal" else "record")
        if kind in {"symlink", "hardlink"}:
            member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            member.linkname = "/outside"
        tar.addfile(member)
        if kind in {"duplicate", "parent"}:
            tar.addfile(tarfile.TarInfo("record" if kind == "duplicate" else "record/child"))
    salt = b"0123456789abcdef"
    encrypted = tmp_path / "bad.enc"
    encrypted.write_bytes(MAGIC + salt + _cipher(PASSWORD, salt).encrypt(data.getvalue()))
    target = tmp_path / "never-created"
    with pytest.raises(ValueError):
        restore(encrypted, PASSWORD, target)
    assert not target.exists()


def test_capture_limit_and_output_boundary(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    root.mkdir()
    (root / "large").write_bytes(b"x" * 32)
    with pytest.raises(ValueError):
        create(root, ["large"], root / "recursive.enc", PASSWORD, quiesced=True)
    monkeypatch.setattr("netadmin.operations.backup.MAX_BYTES", 16)
    with pytest.raises(ValueError):
        create(root, ["large"], tmp_path / "bounded.enc", PASSWORD, quiesced=True)


def test_cli_failure_does_not_print_private_paths(tmp_path, monkeypatch, capsys):
    from netadmin.operations.backup import main

    monkeypatch.setattr(
        "sys.argv",
        [
            "backup",
            "verify",
            "--archive",
            str(tmp_path / "missing-private"),
            "--password-file",
            str(tmp_path / "password"),
        ],
    )
    with pytest.raises(SystemExit):
        main()
    assert "missing-private" not in capsys.readouterr().err
