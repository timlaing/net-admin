"""Route authorization and CSRF tests."""

from pathlib import Path

import pytest
from argon2 import PasswordHasher

from netadmin import create_app
from netadmin.config import Settings


def make_app(tmp_path: Path):  # type: ignore[no-untyped-def]
    app = create_app(
        Settings(
            secret_key="test-secret",  # noqa: S106
            root_password_hash=PasswordHasher().hash("correct-horse-battery-staple"),
            data_dir=tmp_path,
        )
    )
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app


def test_backend_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NETADMIN_SECRET_KEY", "test-secret")
    monkeypatch.setenv("NETADMIN_ROOT_PASSWORD_HASH", "test-hash")
    monkeypatch.setenv("NETADMIN_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NETADMIN_DHCP_BACKEND", raising=False)
    assert Settings.from_env().dhcp_backend == "isc"
    monkeypatch.setenv("NETADMIN_DHCP_BACKEND", "kea")
    assert Settings.from_env().dhcp_backend == "kea"
    monkeypatch.setenv("NETADMIN_DHCP_BACKEND", "bogus")
    with pytest.raises(RuntimeError, match="NETADMIN_DHCP_BACKEND"):
        Settings.from_env()


def test_anonymous_redirected(tmp_path: Path) -> None:
    client = make_app(tmp_path).test_client()
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.location


def test_root_login_and_dashboard(tmp_path: Path) -> None:
    client = make_app(tmp_path).test_client()
    response = client.post(
        "/login",
        data={"username": "root", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 302
    response = client.get("/", headers={"Cookie": response.headers["Set-Cookie"]})
    assert response.status_code == 200
    assert b"Network overview" in response.data


def test_bad_root_login(tmp_path: Path) -> None:
    client = make_app(tmp_path).test_client()
    response = client.post("/login", data={"username": "root", "password": "wrong"})
    assert b"Invalid username" in response.data


def test_ingress_authentication_option_is_strict_and_defaults_to_login(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("NETADMIN_SECRET_KEY", "synthetic")
    monkeypatch.setenv("NETADMIN_ROOT_PASSWORD_HASH", "unused")
    monkeypatch.setenv("NETADMIN_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NETADMIN_INGRESS_REQUIRE_LOGIN", raising=False)
    assert Settings.from_env().ingress_require_login is True
    monkeypatch.setenv("NETADMIN_INGRESS_REQUIRE_LOGIN", "false")
    assert Settings.from_env().ingress_require_login is False
    monkeypatch.setenv("NETADMIN_INGRESS_REQUIRE_LOGIN", "invalid")
    with pytest.raises(RuntimeError, match="NETADMIN_INGRESS_REQUIRE_LOGIN"):
        Settings.from_env()
