"""Faulty CLI paths cannot widen separately installed operator filesystem scopes."""

import pytest

from netadmin.operations import paths


def test_exact_scope_cannot_be_replaced_by_argument(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    root.mkdir()
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(root))
    assert paths.exact(root, "NETADMIN_OPERATIONS_ROOT") == root
    with pytest.raises(ValueError):
        paths.exact(tmp_path, "NETADMIN_OPERATIONS_ROOT")


def test_destination_scope_is_not_cli_controlled(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_BACKUP_DIRECTORY", str(tmp_path))
    assert paths.location(tmp_path / "snapshot.enc", "NETADMIN_BACKUP_DIRECTORY").parent == tmp_path
    for path in (
        tmp_path.parent / "outside.enc",
        tmp_path / ".." / "outside.enc",
        tmp_path / ".ssh",
    ):
        with pytest.raises(ValueError):
            paths.location(path, "NETADMIN_BACKUP_DIRECTORY")


def test_unrelated_credential_stores_and_links_are_refused(tmp_path):
    for name in (".ssh/id_rsa", "../outside", "/absolute", ".aws/credentials"):
        with pytest.raises(ValueError):
            paths.relative(name)
    (tmp_path / "state").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "state", target_is_directory=True)
    assert paths.existing(tmp_path, "state").name == "state"
    with pytest.raises(ValueError):
        paths.existing(tmp_path, "link")


def test_missing_or_global_operation_boundary_is_refused(monkeypatch):
    monkeypatch.delenv("NETADMIN_OPERATIONS_ROOT", raising=False)
    with pytest.raises(ValueError):
        paths.configured("NETADMIN_OPERATIONS_ROOT")
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", "/")
    with pytest.raises(ValueError):
        paths.configured("NETADMIN_OPERATIONS_ROOT")
