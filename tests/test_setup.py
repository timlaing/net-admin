"""First-run setup wizard tests."""

import importlib
from pathlib import Path

import pytest

from netadmin.setup import create_setup_app, env_path, write_env_file

INGRESS = {"X-Ingress-Path": "/api/hassio/ingress/token"}


def make_wizard(tmp_path: Path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    app = create_setup_app()
    app.config.update(
        TESTING=True, WTF_CSRF_ENABLED=False, APPLICATION_ROOT=INGRESS["X-Ingress-Path"]
    )
    return app.test_client()


def test_hidden_outside_ingress(tmp_path: Path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    assert client.get("/").status_code == 404
    assert client.get("/", headers=INGRESS).status_code == 200


def test_full_wizard_flow(tmp_path: Path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    response = client.post(
        "/",
        headers=INGRESS,
        data={
            "password": "correct-horse-battery-staple",
            "confirm": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 200
    assert b"Network services" in response.data
    response = client.post(
        "/services",
        headers=INGRESS,
        data={
            "dns_server": "dns.internal",
            "dns_zones": "internal.laingcorp.co.uk",
            "dhcp_agent_url": "https://dhcp.internal:8081",
            "radius_agent_url": "https://radius.internal:8082",
            "radius_secret": "",
            "tsig_secret": "",
        },
    )
    assert response.status_code == 200
    assert b"Review and apply" in response.data
    response = client.post("/apply", headers=INGRESS, data={"confirmed": "y"})
    assert response.status_code == 200
    assert b"Restart the add-on" in response.data
    content = (tmp_path / "netadmin.env").read_text()
    assert "NETADMIN_SECRET_KEY='" in content
    assert "NETADMIN_ROOT_PASSWORD_HASH='$argon2id" in content
    assert "NETADMIN_RADIUS_SECRET='" in content
    assert "NETADMIN_DNS_SERVER='dns.internal'" in content
    assert oct((tmp_path / "netadmin.env").stat().st_mode & 0o777) == "0o640"


def test_apply_requires_confirmation(tmp_path: Path, monkeypatch) -> None:
    client = make_wizard(tmp_path, monkeypatch)
    client.post(
        "/",
        headers=INGRESS,
        data={
            "password": "correct-horse-battery-staple",
            "confirm": "correct-horse-battery-staple",
        },
    )
    client.post("/services", headers=INGRESS, data={"dns_server": "dns"})
    response = client.post("/apply", headers=INGRESS, data={})
    assert response.status_code == 400
    assert not (tmp_path / "netadmin.env").exists()


def test_configured_env_locks_wizard(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    write_env_file({"NETADMIN_SECRET_KEY": "existing"})
    app = create_setup_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    response = app.test_client().get("/", headers=INGRESS)
    assert b"Configuration written" in response.data
    assert b"Emergency root account" not in response.data


def test_env_path_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "custom.env"))
    assert env_path() == tmp_path / "custom.env"


def test_env_path_rejects_relative(monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", "netadmin.env")
    with pytest.raises(ValueError, match="must be absolute"):
        env_path()


def test_env_path_rejects_traversal(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / ".." / "netadmin.env"))
    with pytest.raises(ValueError, match="must be absolute"):
        env_path()


def test_wizard_reports_bad_env_file(monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", "netadmin.env")
    app = create_setup_app()
    app.config.update(WTF_CSRF_ENABLED=False)
    response = app.test_client().get("/", headers=INGRESS)
    assert response.status_code == 500
    assert b"NETADMIN_ENV_FILE must be absolute" in response.data


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
