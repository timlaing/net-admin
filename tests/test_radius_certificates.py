"""Certificate lifecycle tests use synthetic keys and no live RADIUS material."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netadmin.agents.radius import create_radius_agent
from netadmin.services.radius_certificates import (
    PEM,
    certificate_changes,
    certificate_info,
    issue_certificate,
    issue_crl,
    key_matches,
    load_signing_key,
    private_pem,
    replacement_key,
)
from tests.test_multi_service_ui import admin_client

AUTH = {"Authorization": "Bearer synthetic"}
PASSWORD = b"synthetic-password"


@pytest.fixture
def material(tmp_path):
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic RADIUS CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "radius.example.net")]))
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=100))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("radius.example.net")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(PEM))
    (tmp_path / "ca.key").write_bytes(private_pem(key, PASSWORD))
    (tmp_path / "server.pem").write_bytes(
        private_pem(server_key, PASSWORD) + server.public_bytes(PEM)
    )
    return tmp_path, ca, server, key


def prepared(material, action, crl=None):
    directory = material[0]
    return certificate_changes(
        (directory / "ca.pem").read_bytes(),
        (directory / "ca.key").read_bytes(),
        (directory / "server.pem").read_bytes(),
        crl,
        PASSWORD,
        action,
    )


@pytest.mark.parametrize("action", ["renew-server", "revoke-server", "renew-ca", "retire-ca"])
def test_signed_lifecycle_preserves_identity_and_records_revocation(material, action):
    _, old_ca, old_server, _ = material
    changes = prepared(material, action)
    ca = x509.load_pem_x509_certificate(
        changes.get("ca.pem", old_ca.public_bytes(PEM).decode()).encode()
    )
    server = x509.load_pem_x509_certificate(
        changes.get("server.pem", old_server.public_bytes(PEM).decode()).encode()
    )
    ca.verify_directly_issued_by(ca)
    server.verify_directly_issued_by(ca)
    assert server.subject == old_server.subject
    assert (
        server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        == old_server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    )
    if action == "renew-ca":
        assert server.serial_number == old_server.serial_number
        assert ca.serial_number != old_ca.serial_number
        assert ca.public_key().public_numbers() == old_ca.public_key().public_numbers()
    else:
        assert server.serial_number != old_server.serial_number
        assert key_matches(server, load_signing_key(changes["server.pem"].encode(), PASSWORD))
    crl = x509.load_pem_x509_crl(changes["netadmin-crl.pem"].encode())
    assert crl.issuer == ca.subject
    if action == "revoke-server":
        assert crl.get_revoked_certificate_by_serial_number(old_server.serial_number)
    elif action == "retire-ca":
        assert ca.public_key().public_numbers() != old_ca.public_key().public_numbers()
        retired = x509.load_pem_x509_crl(
            changes[f"retired-{old_ca.serial_number:x}-crl.pem"].encode()
        )
        assert retired.get_revoked_certificate_by_serial_number(old_server.serial_number)
        assert "ca.key" in changes


def test_crl_preserves_previous_revocations_and_rejects_bad_signers(material):
    _, ca, server, key = material
    crl = issue_crl(ca, key, None, server)
    updated = issue_crl(ca, key, crl, server)
    assert len(updated) == 1
    assert updated.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValueError):
        issue_crl(ca, wrong, crl)
    with pytest.raises(ValueError):
        prepared(material, "invalid")


def test_expiry_and_unencrypted_key_support(material):
    _, ca, server, key = material
    assert certificate_info(server)["status"] == "Valid"
    assert key_matches(ca, load_signing_key(private_pem(key, b""), b""))
    expired = datetime.now(UTC) - timedelta(days=2)
    builder = (
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(10)
        .not_valid_before(expired - timedelta(days=1))
        .not_valid_after(expired)
    )
    old = builder.sign(key, hashes.SHA256())
    assert certificate_info(old)["status"] == "Expired"
    with pytest.raises(ValueError, match="expired CA"):
        issue_certificate(server, key, old, key)


def agent(material, monkeypatch):
    directory = material[0]
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_CERT_DIR", str(directory))
    monkeypatch.setenv("RADIUS_CERT_KEY_PASSWORD", PASSWORD.decode())
    monkeypatch.setenv("RADIUS_CERT_MANAGEMENT", "true")
    monkeypatch.setattr("netadmin.agents.radius_certificates._protocol_ready", lambda: True)
    monkeypatch.setattr("netadmin.agents.radius_certificates._restart", lambda: None)
    monkeypatch.setattr("netadmin.agents.radius_certificates.subprocess.run", lambda *a, **k: None)
    client = create_radius_agent().test_client()
    status = client.get("/certificates", headers=AUTH).json
    body = {
        "action": "revoke-server",
        "expected_ca": status["ca"]["fingerprint"],
        "expected_server": status["server"]["fingerprint"],
    }
    return client, body


def test_agent_operations_authentication_stale_checks_and_public_downloads(material, monkeypatch):
    client, body = agent(material, monkeypatch)
    assert client.get("/certificates").status_code == 401
    assert client.post("/certificates", json=body).status_code == 401
    assert (
        client.post(
            "/certificates", json={**body, "expected_ca": "stale"}, headers=AUTH
        ).status_code
        == 409
    )
    assert (
        client.post("/certificates", json={**body, "action": "retire-ca"}, headers=AUTH).status_code
        == 400
    )
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 200
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 409
    assert client.get("/certificates", headers=AUTH).json["revoked_count"] == 1
    for kind in ("server", "ca", "crl"):
        response = client.get(f"/certificates/{kind}", headers=AUTH)
        assert response.status_code == 200
        assert "PRIVATE KEY" not in response.text
    assert client.get("/certificates/ca.key", headers=AUTH).status_code == 404
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 403


def test_certificate_validation_failure_rolls_back_all_files(material, monkeypatch):
    client, body = agent(material, monkeypatch)
    directory = material[0]
    original = (directory / "server.pem").read_bytes()

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic validation failure")

    monkeypatch.setattr("netadmin.agents.radius_certificates.subprocess.run", fail)
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 502
    assert (directory / "server.pem").read_bytes() == original
    assert not (directory / "netadmin-crl.pem").exists()
    assert not list(directory.glob("previous-server-*"))


def test_activation_failure_restores_original_and_restarts_old_identity(material, monkeypatch):
    client, body = agent(material, monkeypatch)
    original = (material[0] / "server.pem").read_bytes()
    calls = []

    def restart():
        calls.append((material[0] / "server.pem").read_bytes())
        if len(calls) == 1:
            raise RuntimeError("synthetic startup failure")

    monkeypatch.setattr("netadmin.agents.radius_certificates._restart", restart)
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 502
    assert len(calls) == 2 and calls[0] != original and calls[1] == original


def test_missing_key_and_symlink_block_management(material, monkeypatch):
    client, body = agent(material, monkeypatch)
    directory = material[0]
    (directory / "ca.key").unlink()
    assert client.get("/certificates", headers=AUTH).json["can_manage"] is False
    assert client.post("/certificates", json=body, headers=AUTH).status_code == 409
    (directory / "server.pem").unlink()
    (directory / "server.pem").symlink_to(Path("/not-a-real-certificate"))
    assert client.get("/certificates", headers=AUTH).json["available"] is False


def test_certificate_ui_confirmations_and_read_only_guards(tmp_path, material):
    app, client = admin_client(tmp_path)
    _, ca, server, _ = material
    calls = []
    remote = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: (
            {
                "available": True,
                "can_manage": True,
                "ca": certificate_info(ca),
                "server": certificate_info(server),
                "has_crl": False,
            }
            if path == "certificates"
            else {"pem": ca.public_bytes(PEM).decode()}
        ),
        post=lambda path, payload, **kwargs: calls.append((path, payload, kwargs)),
    )
    app.extensions["netadmin_radius"] = remote
    page = client.get("/radius/certificates")
    assert page.status_code == 200
    assert "Revoke and replace server certificate" in page.text
    assert "REPLACE CA" in page.text
    assert "PRIVATE KEY" not in page.text
    assert client.post("/radius/certificates", data={"action": "renew-server"}).status_code == 400
    assert (
        client.post(
            "/radius/certificates", data={"action": "renew-server", "confirm": "yes"}
        ).status_code
        == 302
    )
    assert calls[0][0] == "certificates" and calls[0][2] == {"timeout": 60}
    assert "PRIVATE KEY" not in client.get("/radius/certificates/download/server").text
    assert client.get("/radius/certificates/download/key").status_code == 404
    remote.read_only = lambda: True
    assert 'name="action"' not in client.get("/radius/certificates").text
    assert (
        client.post(
            "/radius/certificates", data={"action": "renew-server", "confirm": "yes"}
        ).status_code
        == 403
    )


def test_certificate_ui_requires_csrf_and_admin(tmp_path):
    app, client = admin_client(tmp_path)
    app.config["WTF_CSRF_ENABLED"] = True
    assert (
        client.post(
            "/radius/certificates", data={"action": "renew-server", "confirm": "yes"}
        ).status_code
        == 400
    )
    app.config["WTF_CSRF_ENABLED"] = False
    token = app.extensions["netadmin_store"].create_session("standard", "standard", 60)
    client.set_cookie("netadmin_session", token)
    assert client.get("/radius/certificates").status_code == 403
    assert client.get("/radius/certificates/download/ca").status_code == 403
    assert (
        client.post(
            "/radius/certificates", data={"action": "renew-server", "confirm": "yes"}
        ).status_code
        == 403
    )


def test_empty_crl_has_expiry_and_refresh_preserves_server(material, monkeypatch):
    client, body = agent(material, monkeypatch)
    response = client.post("/certificates", json={**body, "action": "refresh-crl"}, headers=AUTH)
    assert response.status_code == 200
    status = client.get("/certificates", headers=AUTH).json
    assert status["has_crl"] and status["crl_expires"]
    assert status["revoked_count"] == 0
    assert status["server"]["fingerprint"] == body["expected_server"]


def test_ec_ca_renewal_and_retirement_preserve_curve(material):
    _, ca, _, _ = material
    key = ec.generate_private_key(ec.SECP384R1())
    authority = issue_certificate(ca, key, ca, key, is_ca=True)
    replacement = replacement_key(authority, is_ca=True)
    assert isinstance(replacement, ec.EllipticCurvePrivateKey)
    assert replacement.curve.name == key.curve.name
    renewed = issue_certificate(authority, replacement, authority, replacement, is_ca=True)
    renewed.verify_directly_issued_by(renewed)
    assert renewed.signature_hash_algorithm.name == "sha384"
