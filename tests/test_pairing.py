"""Enrollment pins host identity and cannot replace settings before validation."""

import importlib.util
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from netadmin import pairing, pairing_exchange
from netadmin.preferences import read_env_file
from tests.test_connections import client_for
from tests.test_connections import runtime as runtime

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def deployment(tmp_path):
    """Generate isolated synthetic credentials with the actual host installer."""
    spec = importlib.util.spec_from_file_location(
        "pairing_installer", ROOT / "scripts/install_services.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = tmp_path / "deployment"
    directory.mkdir()
    module.certificates(directory, "192.0.2.10", ["ca"])
    (directory / "installation.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "project": "netadmin-services",
                "address": "127.0.0.1",
                "dns": "no",
                "dhcp": "none",
                "radius": "no",
                "ca": "yes",
            }
        )
    )
    (directory / "agents.env").write_text("NETADMIN_AGENT_TOKEN=" + "a" * 48 + "\n")
    (directory / "secrets").mkdir()
    (directory / "secrets/management-token").write_text("b" * 48)
    return directory


def payload_for(directory):
    """Return only client identity material and management tokens."""
    return {
        "schema": 1,
        "services": ["ca"],
        "address": "192.0.2.10",
        "token": "a" * 48,
        "management_token": "b" * 48,
        "ca": (directory / "transport/client/ca.crt").read_text(),
        "certificate": (directory / "transport/client/client.crt").read_text(),
        "key": (directory / "transport/client/client.key").read_text(),
    }


def test_pairing_imports_private_files_and_applies(runtime, monkeypatch, deployment):
    """Import into a unique private directory without changing account settings."""
    client = client_for(runtime, monkeypatch)
    monkeypatch.setattr(pairing, "claim", lambda _code: payload_for(deployment))
    response = client.post("/settings/pair", data={"pairing_code": "synthetic"})
    assert response.status_code == 302
    settings = client.application.extensions["netadmin_settings"]
    assert settings.ca_enabled
    assert settings.ca_agent_url == "https://192.0.2.10:8084"
    assert settings.secret_key == runtime.secret_key
    assert settings.agent_key.stat().st_mode & 0o777 == 0o600
    assert settings.agent_key.parent.stat().st_mode & 0o777 == 0o700
    assert read_env_file()["NETADMIN_CA_MANAGEMENT_TOKEN"] == "b" * 48
    assert "a" * 48 not in client.get("/settings").text


@pytest.mark.parametrize(
    "role,addon,expected", [("standard", True, 403), (None, True, 302), ("admin", False, 403)]
)
def test_pairing_requires_admin_and_persistent_settings(
    runtime, monkeypatch, role, addon, expected
):
    """Reject enrollment before network access for unauthorized clients."""
    client = client_for(runtime, monkeypatch, role=role, addon=addon)
    monkeypatch.setattr(pairing, "claim", lambda _: pytest.fail("must not contact host"))
    assert client.post("/settings/pair").status_code == expected


def test_invalid_credentials_keep_active_settings(runtime, monkeypatch, deployment):
    """Never save a key which fails certificate validation."""
    client = client_for(runtime, monkeypatch)
    payload = payload_for(deployment)
    payload["key"] = (deployment / "transport/authority/ca.key").read_text()
    monkeypatch.setattr(pairing, "claim", lambda _: payload)
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 400
    assert not read_env_file()
    assert client.application.extensions["netadmin_settings"] is runtime


def test_pin_checked_before_authorization(monkeypatch):
    """Do not disclose the secret to a substituted TLS certificate."""
    peer = SimpleNamespace(getpeercert=lambda **_: b"wrong peer")
    connection = SimpleNamespace(
        sock=peer,
        connect=lambda: None,
        close=lambda: None,
        request=lambda *_a, **_k: pytest.fail("secret transmitted before pin validation"),
    )
    monkeypatch.setattr(
        pairing_exchange.http.client, "HTTPSConnection", lambda *_a, **_k: connection
    )
    code = "netadmin-pair://192.0.2.10:8085/" + "a" * 43 + "#" + "0" * 64
    with pytest.raises(ValueError, match="identity"):
        pairing_exchange.claim(code)


def test_real_tls_exchange_consumed_once(deployment, monkeypatch, capsys):
    """Exercise the real TLS listener and client; a consumed server closes."""
    original = pairing_exchange.parse_code
    monkeypatch.setattr(
        pairing_exchange,
        "parse_code",
        lambda code: ("127.0.0.1", *original(code.replace("127.0.0.1", "192.0.2.10"))[1:]),
    )
    thread = threading.Thread(target=pairing_exchange.serve, args=(deployment, 0, 5), daemon=True)
    thread.start()
    code = ""
    for _ in range(100):
        output = capsys.readouterr().out
        code = next(
            (line for line in output.splitlines() if line.startswith("netadmin-pair://")), ""
        )
        if code:
            break
        time.sleep(0.02)
    assert code
    bad_code = code.replace(code.split("/")[-1].split("#")[0], "z" * 43)
    with pytest.raises(ValueError, match="expired or already used"):
        pairing_exchange.claim(bad_code)
    payload = pairing_exchange.claim(code)
    thread.join(timeout=6)
    assert not thread.is_alive()
    assert payload["token"] == "a" * 48
    assert "ca.key" not in payload
    assert "authority" not in payload
    with pytest.raises(OSError):
        pairing_exchange.claim(code)


def test_pairing_preserves_csrf_protection(runtime, monkeypatch):
    """An administrator session alone cannot authorize a cross-site enrollment."""
    client = client_for(runtime, monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    monkeypatch.setattr(pairing, "claim", lambda _: pytest.fail("must not contact host"))
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 400
