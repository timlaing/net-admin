"""Regression coverage for Supervisor's stripped-path ingress requests."""

from urllib.parse import parse_qs, urlsplit

import pytest

from netadmin.setup import create_setup_app
from tests.test_app import make_app

PREFIX = "/api/hassio_ingress/synthetic-token"
HEADERS = {"X-Ingress-Path": PREFIX, "X-Forwarded-Proto": "https"}


def test_ingress_redirect_assets_and_https_notice(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    client = make_app(tmp_path).test_client()
    response = client.get("/dns?zone=example.net", headers=HEADERS)
    target = urlsplit(response.location)
    assert target.path == f"{PREFIX}/login"
    assert parse_qs(target.query)["next"] == [f"{PREFIX}/dns?zone=example.net"]
    client.application.config["WTF_CSRF_ENABLED"] = True
    page = client.get("/login", headers=HEADERS)
    assert f'href="{PREFIX}/static/app.css"'.encode() in page.data
    assert f'href="{PREFIX}/"'.encode() in page.data
    assert b"Open Home Assistant over HTTPS" not in page.data
    assert f"Path={PREFIX}" in page.headers["Set-Cookie"]
    assert "Secure" in page.headers["Set-Cookie"]
    page = client.get("/login", headers={**HEADERS, "X-Forwarded-Proto": "http"})
    assert b"Open Home Assistant over HTTPS" in page.data
    assert client.get("/static/app.css", headers=HEADERS).status_code == 200


@pytest.mark.parametrize(
    "next_path",
    [
        None,
        "/dns",
        "//example.net",
        "/api/other-app/",
        f"{PREFIX}/../other-app/",
        f"{PREFIX}/%2e%2e/other-app/",
        f"{PREFIX}/%5cother-app/",
    ],
)
def test_ingress_login_stays_inside_app(tmp_path, monkeypatch, next_path) -> None:
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    app = make_app(tmp_path)
    app.config["APPLICATION_ROOT"] = PREFIX
    client = app.test_client()
    response = client.post(
        "/login",
        query_string={"next": next_path} if next_path else {},
        headers=HEADERS,
        data={"username": "root", "password": "correct-horse-battery-staple"},
    )
    assert response.location == f"{PREFIX}/"
    assert f"Path={PREFIX}" in response.headers["Set-Cookie"]
    assert client.get("/", headers=HEADERS).status_code == 200
    response = client.post("/logout", headers=HEADERS)
    assert response.location == f"{PREFIX}/login"
    assert f"Path={PREFIX}" in response.headers["Set-Cookie"]
    assert client.get("/", headers=HEADERS).status_code == 302


def test_ingress_login_preserves_local_destination(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    response = (
        make_app(tmp_path)
        .test_client()
        .post(
            "/login",
            query_string={"next": f"{PREFIX}/dns?zone=example.net"},
            headers=HEADERS,
            data={"username": "root", "password": "correct-horse-battery-staple"},
        )
    )
    assert response.location == f"{PREFIX}/dns?zone=example.net"


@pytest.mark.parametrize("prefix", ["//example.net", "/unexpected", PREFIX + "/../other"])
def test_rejects_invalid_ingress_paths(tmp_path, monkeypatch, prefix) -> None:
    monkeypatch.setenv("NETADMIN_ADDON", "1")
    response = make_app(tmp_path).test_client().get("/login", headers={"X-Ingress-Path": prefix})
    assert response.status_code == 400


def test_standalone_ignores_ingress_headers(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NETADMIN_ADDON", raising=False)
    response = make_app(tmp_path).test_client().get("/", headers=HEADERS)
    assert urlsplit(response.location).path == "/login"


def test_setup_uses_ingress_urls_and_secure_cookie(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    app = create_setup_app()
    app.config.update(TESTING=True, APPLICATION_ROOT=PREFIX)
    response = app.test_client().get("/", headers=HEADERS)
    assert f'action="{PREFIX}/"'.encode() in response.data
    assert "Secure" in response.headers["Set-Cookie"]
    assert f"Path={PREFIX}" in response.headers["Set-Cookie"]
