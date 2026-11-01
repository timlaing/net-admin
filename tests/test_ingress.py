"""Regression coverage for Supervisor's stripped-path ingress requests."""

import re
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from flask.testing import FlaskClient

from netadmin.setup import create_setup_app
from tests.test_app import make_app as base_app


def make_app(tmp_path):
    app = base_app(tmp_path)
    app.config["TESTING"] = True
    app.test_client_class = SupervisorClient
    return app


class SupervisorClient(FlaskClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.environ_base["REMOTE_ADDR"] = "172.30.32.2"


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
    assert b"over HTTPS to sign in" not in page.data
    assert f"Path={PREFIX}" in page.headers["Set-Cookie"]
    assert "Secure" in page.headers["Set-Cookie"]
    page = client.get("/login", headers={**HEADERS, "X-Forwarded-Proto": "http"})
    assert b"over HTTPS to sign in" not in page.data
    page = client.get("/login", headers={"X-Ingress-Path": PREFIX})
    assert b"over HTTPS to sign in" not in page.data
    assert client.get("/static/app.css", headers=HEADERS).status_code == 200


@pytest.mark.parametrize("addon", [False, True])
def test_direct_http_warns_but_https_does_not(tmp_path, monkeypatch, addon) -> None:
    if addon:
        monkeypatch.setenv("NETADMIN_ADDON", "1")
    else:
        monkeypatch.delenv("NETADMIN_ADDON", raising=False)
    client = make_app(tmp_path).test_client()
    page = client.get("/login", base_url="http://localhost")
    assert b"Open NetAdmin over HTTPS to sign in." in page.data
    page = client.get("/login", base_url="https://localhost")
    assert b"over HTTPS to sign in" not in page.data


def test_standalone_ingress_header_cannot_hide_direct_http_notice(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NETADMIN_ADDON", raising=False)
    page = make_app(tmp_path).test_client().get("/login", headers=HEADERS)
    assert b"Open NetAdmin over HTTPS to sign in." in page.data


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
    app.test_client_class = SupervisorClient
    app.config.update(TESTING=True, APPLICATION_ROOT=PREFIX)
    response = app.test_client().get("/", headers=HEADERS)
    assert f'action="{PREFIX}/"'.encode() in response.data
    assert "Secure" in response.headers["Set-Cookie"]
    assert f"Path={PREFIX}" in response.headers["Set-Cookie"]


def delegated_client(tmp_path, monkeypatch, require_login=False, addon=True):

    monkeypatch.setenv("NETADMIN_ADDON", "1" if addon else "0")
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    monkeypatch.setenv("NETADMIN_SUPERVISOR_VERSION", "2026.10.5")
    app = make_app(tmp_path)
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], ingress_require_login=require_login
    )
    app.config["APPLICATION_ROOT"] = PREFIX if addon else "/"
    return app.test_client()


ADMIN = {
    **HEADERS,
    "X-Remote-User-Id": "synthetic-ha-id",
    "X-Remote-User-Display-Name": "HA Administrator",
    "X-Remote-User-Groups": "system-users,system-admin",
}


def test_delegated_ingress_admin_without_portable_session(tmp_path, monkeypatch) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    response = client.get("/", headers=ADMIN)
    assert response.status_code == 200
    assert b"HA Administrator" in response.data
    assert b"Home Assistant session" in response.data
    assert b"Sign out</button>" not in response.data
    assert b"Change password</a>" not in response.data
    assert "netadmin_session=" not in str(response.headers.getlist("Set-Cookie"))
    # Losing the HA identity never leaves a local administrator session behind.
    assert client.get("/", headers=HEADERS).status_code == 302
    assert client.get("/").status_code == 302
    assert client.get("/settings", headers=ADMIN).status_code == 200


def test_required_ingress_login_ignores_admin_headers(tmp_path, monkeypatch) -> None:
    client = delegated_client(tmp_path, monkeypatch, require_login=True)
    assert client.get("/", headers=ADMIN).status_code == 302
    assert b"Network administration" in client.get("/login", headers=ADMIN).data


@pytest.mark.parametrize(
    "headers",
    [
        HEADERS,
        {**ADMIN, "X-Remote-User-Id": ""},
        {**ADMIN, "X-Remote-User-Id": "invalid id"},
        {**ADMIN, "X-Remote-User-Groups": ""},
    ],
)
def test_missing_identity_falls_back_to_login(tmp_path, monkeypatch, headers) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    assert client.get("/", headers=headers).status_code == 302


@pytest.mark.parametrize("groups", ["system-users", "system-admin-other", "system-read-only"])
def test_non_admin_identity_is_denied_even_with_local_cookie(tmp_path, monkeypatch, groups) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    token = client.application.extensions["netadmin_store"].create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", token, path=PREFIX)
    assert client.get("/", headers={**ADMIN, "X-Remote-User-Groups": groups}).status_code == 403


@pytest.mark.parametrize("peer", ["127.0.0.1", "172.30.33.5", "172.30.32.3"])
def test_forged_ingress_headers_from_other_peers_are_denied(tmp_path, monkeypatch, peer) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    response = client.get(
        "/",
        headers={**ADMIN, "X-Forwarded-For": "172.30.32.2"},
        environ_overrides={"REMOTE_ADDR": peer},
    )
    assert response.status_code == 403
    assert client.get("/", environ_overrides={"REMOTE_ADDR": peer}).status_code == 302


def test_delegation_is_never_enabled_in_standalone(tmp_path, monkeypatch) -> None:
    client = delegated_client(tmp_path, monkeypatch, addon=False)
    assert client.get("/", headers=ADMIN).status_code == 302


def test_delegated_login_cannot_mint_session_and_password_stays_in_ha(
    tmp_path, monkeypatch
) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    for path in ("/login", "/password"):
        response = client.post(
            path,
            headers=ADMIN,
            data={"username": "root", "password": "correct-horse-battery-staple"},
        )
        assert response.status_code == 302
        assert response.location == PREFIX + "/"
        assert "netadmin_session=" not in str(response.headers.getlist("Set-Cookie"))
    assert client.post("/logout", headers=ADMIN).location == PREFIX + "/"
    assert client.get("/", headers=ADMIN).status_code == 200


def test_delegated_mutations_require_csrf_and_use_stable_audit_identity(
    tmp_path, monkeypatch
) -> None:

    client = delegated_client(tmp_path, monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/settings", headers=ADMIN).status_code == 400
    response = client.get("/settings", headers=ADMIN)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    response = client.post(
        "/settings",
        headers={**ADMIN, "Referer": "https://localhost" + PREFIX + "/settings"},
        data={"csrf_token": token},
    )
    assert response.status_code == 302
    events = client.application.extensions["netadmin_store"].recent_audit()
    assert events[0]["username"] == "ha:synthetic-ha-id"
    assert events[0]["action"] == "settings.connections"
    # Reloading connections preserves the Supervisor-controlled authentication policy.
    assert client.application.extensions["netadmin_settings"].ingress_require_login is False


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_ingress_local_login_and_csrf_follow_frontend_scheme(tmp_path, monkeypatch, scheme):
    client = delegated_client(tmp_path, monkeypatch, require_login=True)
    client.application.config["WTF_CSRF_ENABLED"] = True
    headers = {**HEADERS, "X-Forwarded-Proto": scheme}
    base_url = f"{scheme}://localhost{PREFIX}"
    page = client.get("/login", base_url=base_url, headers=headers)
    cookie = page.headers["Set-Cookie"]
    assert ("; Secure;" in cookie) == (scheme == "https")
    assert f"Path={PREFIX}" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text).group(1)
    action_headers = {**headers, "Referer": base_url + "/login"}
    assert client.post("/login", base_url=base_url, headers=action_headers).status_code == 400
    response = client.post(
        "/login",
        base_url=base_url,
        headers=action_headers,
        data={
            "csrf_token": token,
            "username": "root",
            "password": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 302
    cookie = next(
        c for c in response.headers.getlist("Set-Cookie") if c.startswith("netadmin_session=")
    )
    assert ("; Secure;" in cookie) == (scheme == "https")
    assert f"Path={PREFIX}" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert client.get("/", base_url=base_url, headers=headers).status_code == 200
    assert client.get("/", base_url=f"{scheme}://localhost").status_code == 302


def test_http_delegated_ingress_supports_csrf_protected_posts(tmp_path, monkeypatch):
    client = delegated_client(tmp_path, monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    headers = {**ADMIN, "X-Forwarded-Proto": "http"}
    base_url = "http://localhost" + PREFIX
    response = client.get("/settings", base_url=base_url, headers=headers)
    assert "; Secure;" not in response.headers["Set-Cookie"]
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    for data in ({}, {"csrf_token": "invalid"}):
        assert (
            client.post("/settings", base_url=base_url, headers=headers, data=data).status_code
            == 400
        )
    response = client.post(
        "/settings", base_url=base_url, headers=headers, data={"csrf_token": token}
    )
    assert response.status_code == 302
    assert client.application.extensions["netadmin_settings"].dns_enabled is False


@pytest.mark.parametrize("addon", [False, True])
def test_direct_http_cookies_stay_secure(tmp_path, monkeypatch, addon):
    monkeypatch.setenv("NETADMIN_ADDON", "1" if addon else "0")
    client = make_app(tmp_path).test_client()
    client.application.config["WTF_CSRF_ENABLED"] = True
    # A forwarded scheme without a verified ingress path does not opt out.
    headers = {"X-Forwarded-Proto": "http"}
    response = client.get("/login", base_url="http://localhost", headers=headers)
    assert "; Secure;" in response.headers["Set-Cookie"]
    client.application.config["WTF_CSRF_ENABLED"] = False
    response = client.post(
        "/login",
        base_url="http://localhost",
        headers=headers,
        data={"username": "root", "password": "correct-horse-battery-staple"},
    )
    assert "; Secure;" in response.headers["Set-Cookie"]


def test_http_setup_cookie_supports_csrf_protected_account_creation(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(tmp_path / "netadmin.env"))
    app = create_setup_app()
    app.test_client_class = SupervisorClient
    app.config.update(TESTING=True, APPLICATION_ROOT=PREFIX)
    client = app.test_client()
    headers = {"X-Ingress-Path": PREFIX, "X-Forwarded-Proto": "http"}
    base_url = "http://localhost" + PREFIX
    response = client.get("/", base_url=base_url, headers=headers)
    assert "; Secure;" not in response.headers["Set-Cookie"]
    assert f"Path={PREFIX}" in response.headers["Set-Cookie"]
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    assert client.post("/", base_url=base_url, headers=headers).status_code == 400
    response = client.post(
        "/",
        base_url=base_url,
        headers=headers,
        data={
            "csrf_token": token,
            "password": "long-setup-password",
            "confirm": "long-setup-password",
        },
    )
    assert response.status_code == 200
    assert b"Setup complete" in response.data
    assert (tmp_path / "netadmin.env").is_file()


@pytest.mark.parametrize("version", ["", "2026.10.0", "2026.10.4", "2026.11.0.dev0", "unknown"])
def test_old_or_unknown_supervisor_never_trusts_group_headers(
    tmp_path, monkeypatch, version
) -> None:
    client = delegated_client(tmp_path, monkeypatch)
    monkeypatch.setenv("NETADMIN_SUPERVISOR_VERSION", version)
    assert client.get("/", headers=ADMIN).status_code == 302
