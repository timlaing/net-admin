"""First-run account creation and configuration persistence tests."""

import importlib
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from netadmin.preferences import env_path, read_env_file, write_env_file
from netadmin.setup import create_setup_app

INGRESS = {"X-Ingress-Path": "/api/hassio/ingress/token"}


def make_wizard(tmp_path: Path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    app = create_setup_app()
    app.config.update(
        TESTING=True, WTF_CSRF_ENABLED=False, APPLICATION_ROOT=INGRESS["X-Ingress-Path"]
    )
    return app.test_client()


def test_hidden_outside_ingress(tmp_path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    assert client.get("/").status_code == 404
    assert client.get("/", headers=INGRESS).status_code == 200


def test_account_setup_needs_no_external_services(tmp_path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    response = client.post(
        "/",
        headers=INGRESS,
        data={
            "password": "correct-horse-battery-staple",
            "confirm": "correct-horse-battery-staple",
        },
    )
    assert b"Restart the add-on" in response.data
    saved = read_env_file()
    assert PasswordHasher().verify(
        saved["NETADMIN_ROOT_PASSWORD_HASH"], "correct-horse-battery-staple"
    )
    assert all(saved[f"NETADMIN_{name}_ENABLED"] == "false" for name in ["DNS", "DHCP", "RADIUS"])
    assert "NETADMIN_RADIUS_SECRET" not in saved
    assert "NETADMIN_AGENT_TOKEN" not in saved
    assert "Set-Cookie" not in response.headers  # No password/hash/secret session payload.
    assert (tmp_path / "netadmin.env").stat().st_mode & 0o777 == 0o640
    assert client.post("/services", headers=INGRESS).status_code == 404
    assert client.post("/apply", headers=INGRESS).status_code == 404


def test_invalid_password_does_not_write_configuration(tmp_path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    response = client.post("/", headers=INGRESS, data={"password": "short", "confirm": "other"})
    assert b"between 12 and 1024" in response.data
    assert not (tmp_path / "netadmin.env").exists()


def test_configured_env_locks_wizard(tmp_path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    write_env_file({"NETADMIN_SECRET_KEY": "existing"})
    before = (tmp_path / "netadmin.env").read_bytes()
    response = client.post(
        "/",
        headers=INGRESS,
        data={"password": "different-root-password", "confirm": "different-root-password"},
    )
    assert b"Configuration written" in response.data
    assert b"Emergency root account" not in response.data
    assert (tmp_path / "netadmin.env").read_bytes() == before


def test_env_path_override(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "custom.env"))
    assert env_path() == tmp_path / "custom.env"


@pytest.mark.parametrize("path", ["netadmin.env", "/config/../netadmin.env"])
def test_env_path_rejects_unsafe_paths(monkeypatch, path) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", path)
    with pytest.raises(ValueError, match="must be absolute"):
        env_path()


def test_wizard_reports_bad_env_file(monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", "netadmin.env")
    app = create_setup_app()
    app.config.update(WTF_CSRF_ENABLED=False)
    response = app.test_client().get("/", headers=INGRESS)
    assert response.status_code == 500
    assert b"NETADMIN_ENV_FILE" in response.data


def test_wsgi_falls_back_to_wizard_in_addon_mode(monkeypatch) -> None:
    monkeypatch.delenv("NETADMIN_SECRET_KEY", raising=False)
    monkeypatch.delenv("NETADMIN_ROOT_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    module = importlib.reload(importlib.import_module("netadmin.wsgi"))
    assert module.app.name == "netadmin.setup"


def test_wsgi_reraises_without_addon_flag(monkeypatch) -> None:
    monkeypatch.delenv("NETADMIN_SECRET_KEY", raising=False)
    monkeypatch.delenv("NETADMIN_ROOT_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("NETADMIN_ADDON", raising=False)
    module = importlib.import_module("netadmin.wsgi")
    with pytest.raises(RuntimeError, match="NETADMIN_SECRET_KEY"):
        module.build_app()
