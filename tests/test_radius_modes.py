"""Authentication changes must gate outer methods independently of PEAP's inner method."""

from types import SimpleNamespace

import httpx
import pytest

from netadmin.agents.radius import create_radius_agent
from netadmin.services.radius_modes import configure, inventory
from tests.test_multi_service_ui import admin_client

EAP = """eap {
 default_eap_type = md5
 tls-config tls-common {
  certificate_file = ${certdir}/server.pem
  private_key_password = "private # { } value"
 }
 md5 {
 }
 tls {
  tls = tls-common
 }
 peap {
  tls = tls-common
  default_eap_type = mschapv2
  virtual_server = inner-tunnel
 }
 mschapv2 {
  identity = "Private server name"
 }
}
"""
INNER = """server inner-tunnel {
 authorize {
  files
  eap {
   ok = return
  }
 }
 authenticate {
  eap
 }
}
"""
AUTH = {"Authorization": "Bearer synthetic"}


def test_modes_round_trip_preserves_tls_and_inner_password_method():
    eap, inner = configure(EAP, INNER, ["peap"], "peap")
    status = inventory(eap, inner)
    assert status["enabled"] == ["peap"]
    assert status["other_methods"] == []
    assert status["preferred"] == "peap"
    assert status["uses_certificates"] is True
    assert 'private_key_password = "private # { } value"' in eap
    assert "netadmin_inner" in inner
    optional = INNER.replace("  eap", "  -eap")
    assert "-netadmin_inner" in configure(EAP, optional, ["peap"], "peap")[1]
    assert 'identity = "Private server name"' in eap
    assert "use_tunneled_reply = yes" in eap
    eap, inner = configure(eap, inner, ["mschapv2"], "mschapv2")
    assert inventory(eap, inner)["uses_certificates"] is False
    eap, inner = configure(eap, inner, ["mschapv2", "peap", "tls"], "tls")
    assert inventory(eap, inner)["enabled"] == ["mschapv2", "peap", "tls"]
    assert "configurable_client_cert = no" in eap


@pytest.mark.parametrize(
    "enabled,preferred",
    [([], ""), (["unknown"], "unknown"), (["peap"], "tls"), (["peap", "peap"], "peap")],
)
def test_invalid_modes_rejected(enabled, preferred):
    with pytest.raises(ValueError):
        configure(EAP, INNER, enabled, preferred)


def test_complex_or_duplicate_configuration_rejected():
    with pytest.raises(ValueError):
        configure(EAP + EAP, INNER, ["peap"], "peap")
    custom_inner = INNER.replace("  eap\n", "  other_eap\n")
    with pytest.raises(ValueError):
        configure(EAP, custom_inner, ["peap"], "peap")
    included = EAP.replace(" default_eap_type = md5", "$INCLUDE custom\n default_eap_type = md5")
    with pytest.raises(ValueError):
        configure(
            included,
            INNER,
            ["peap"],
            "peap",
        )


def agent(tmp_path, monkeypatch):
    eap = tmp_path / "eap"
    inner = tmp_path / "inner-tunnel"
    eap.write_text(EAP)
    inner.write_text(INNER)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_EAP_FILE", str(eap))
    monkeypatch.setenv("RADIUS_INNER_TUNNEL_FILE", str(inner))
    monkeypatch.setenv("RADIUS_CERT_DIR", str(tmp_path))
    monkeypatch.setenv("RADIUS_AUTH_MANAGEMENT", "true")
    monkeypatch.setattr("netadmin.agents.radius_modes._protocol_ready", lambda: True)
    monkeypatch.setattr("netadmin.agents.radius_modes._restart", lambda: None)
    monkeypatch.setattr("netadmin.agents.radius_modes.subprocess.run", lambda *a, **k: None)
    return create_radius_agent().test_client(), eap, inner


def test_agent_edits_validate_revision_and_hide_config_values(tmp_path, monkeypatch):
    client, eap, inner = agent(tmp_path, monkeypatch)
    status = client.get("/authentication", headers=AUTH).json
    assert "private" not in str(status)
    payload = {"enabled": ["mschapv2"], "preferred": "mschapv2", "revision": status["revision"]}
    assert client.post("/authentication", headers=AUTH, json=payload).status_code == 200
    assert inventory(eap.read_text(), inner.read_text())["uses_certificates"] is False
    assert (
        client.post("/authentication", headers=AUTH, json=payload).json["status"]
        == "already-applied"
    )
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.post("/authentication", headers=AUTH, json=payload).status_code == 403


def test_agent_failed_validation_rolls_back_both_files(tmp_path, monkeypatch):
    import subprocess

    client, eap, inner = agent(tmp_path, monkeypatch)
    status = client.get("/authentication", headers=AUTH).json

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["radiusd"])

    monkeypatch.setattr("netadmin.agents.radius_modes.subprocess.run", fail)
    response = client.post(
        "/authentication",
        headers=AUTH,
        json={"enabled": ["mschapv2"], "preferred": "mschapv2", "revision": status["revision"]},
    )
    assert response.status_code == 502
    assert eap.read_text() == EAP
    assert inner.read_text() == INNER


def test_ui_hides_unused_certificates_and_allows_explicit_preparation(tmp_path):
    app, client = admin_client(tmp_path)
    status = {
        "available": True,
        "enabled": ["mschapv2"],
        "preferred": "mschapv2",
        "other_methods": [],
        "uses_certificates": False,
        "revision": "synthetic",
        "can_manage": True,
    }
    calls = []
    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: (
            status if path == "authentication" else ({"count": 0} if path == "migration" else [])
        ),
        post=lambda path, payload, **kwargs: calls.append((path, payload)),
    )
    page = client.get("/radius")
    assert page.status_code == 200
    assert ">Certificates</a>" not in page.text
    assert "Authentication modes</a>" in page.text
    assert client.get("/radius/certificates").location.endswith("/radius/authentication")
    page = client.get("/radius/authentication")
    assert "data-mode-certificates hidden" in page.text
    assert 'value="mschapv2" checked' in page.text
    response = client.post(
        "/radius/authentication",
        data={
            "enabled": ["peap", "mschapv2"],
            "preferred": "peap",
            "revision": "synthetic",
            "confirm": "yes",
        },
    )
    assert response.status_code == 302
    assert calls[0] == (
        "authentication",
        {"enabled": ["peap", "mschapv2"], "preferred": "peap", "revision": "synthetic"},
    )
    status["uses_certificates"] = True
    assert ">Certificates</a>" in client.get("/radius").text


def test_unavailable_agent_does_not_claim_certificates_unused(tmp_path):
    app, client = admin_client(tmp_path)

    def fail(path):
        raise httpx.ConnectError("offline")

    app.extensions["netadmin_radius"] = SimpleNamespace(read_only=lambda: False, get=fail)
    assert "Update the RADIUS agent" in client.get("/radius/authentication").text


def test_mode_changes_enforce_ui_authorization_csrf_and_read_only(tmp_path):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_radius"] = SimpleNamespace(read_only=lambda: True)
    assert client.post("/radius/authentication", data={"confirm": "yes"}).status_code == 403
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/radius/authentication", data={"confirm": "yes"}).status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False
    token = app.extensions["netadmin_store"].create_session("alice", "standard", 60)
    client.set_cookie("netadmin_session", token)
    assert client.get("/radius/authentication").status_code == 403
    assert client.post("/radius/authentication", data={"confirm": "yes"}).status_code == 403


def test_agent_failed_activation_restores_files_and_restarts_original(tmp_path, monkeypatch):
    client, eap, inner = agent(tmp_path, monkeypatch)
    status = client.get("/authentication", headers=AUTH).json
    attempts = []

    def restart():
        attempts.append(eap.read_text())
        if len(attempts) == 1:
            raise RuntimeError("Synthetic restart failure")

    monkeypatch.setattr("netadmin.agents.radius_modes._restart", restart)
    response = client.post(
        "/authentication",
        headers=AUTH,
        json={"enabled": ["mschapv2"], "preferred": "mschapv2", "revision": status["revision"]},
    )
    assert response.status_code == 502
    assert len(attempts) == 2
    assert attempts[-1] == EAP
    assert eap.read_text() == EAP
    assert inner.read_text() == INNER


def test_expired_certificates_block_tls_modes_before_config_write(tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    client, eap, inner = agent(tmp_path, monkeypatch)
    for name in ("server.pem", "ca.pem"):
        (tmp_path / name).write_bytes(b"synthetic certificate")
    now = datetime.now(UTC)
    monkeypatch.setattr(
        "netadmin.agents.radius_modes.x509.load_pem_x509_certificate",
        lambda data: SimpleNamespace(
            not_valid_before_utc=now - timedelta(days=2),
            not_valid_after_utc=now - timedelta(days=1),
        ),
    )
    status = client.get("/authentication", headers=AUTH).json
    response = client.post(
        "/authentication",
        headers=AUTH,
        json={"enabled": ["peap"], "preferred": "peap", "revision": status["revision"]},
    )
    assert response.status_code == 400
    assert "prepare valid certificates" in response.json["error"]
    assert eap.read_text() == EAP
    assert inner.read_text() == INNER
