"""Synthetic CSR policy, CA agent, local identity and staged renewal regression tests."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netadmin.agents import radius_renewal, radius_step_ca
from netadmin.agents.ca import create_ca_agent
from netadmin.services.radius_certificates import (
    PEM,
    certificate_changes,
    certificate_options,
    issue_certificate,
    key_matches,
    load_signing_key,
)
from netadmin.services.step_ca import validate_csr, validate_server_chain
from tests.test_multi_service_ui import admin_client
from tests.test_radius_certificates import AUTH, PASSWORD, agent
from tests.test_radius_certificates import material as material


def csr(key=None, *, ca=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "radius.test")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("radius.test")]), False)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(PEM).decode()


@pytest.mark.parametrize("action", ["create-server", "renew-server"])
def test_local_custom_identity_and_one_year(material, monkeypatch, action):
    client, body = agent(material, monkeypatch)
    result = client.post(
        "/certificates",
        headers=AUTH,
        json={
            **body,
            "action": action,
            "common_name": "new.example.test",
            "sans": "new.example.test,192.0.2.15,2001:db8::1",
            "days": "365",
        },
    )
    assert result.status_code == 200, result.json
    cert = x509.load_pem_x509_certificate((material[0] / "server.pem").read_bytes())
    cert.verify_directly_issued_by(material[1])
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "new.example.test"
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(name.value) for name in names] == ["new.example.test", "192.0.2.15", "2001:db8::1"]
    assert (
        timedelta(days=365)
        <= cert.not_valid_after_utc - cert.not_valid_before_utc
        < timedelta(days=366)
    )
    assert key_matches(cert, load_signing_key((material[0] / "server.pem").read_bytes(), PASSWORD))
    assert (
        material[2].public_bytes(PEM)
        == (material[0] / f"previous-server-{material[2].serial_number:x}.crt").read_bytes()
    )


@pytest.mark.parametrize(
    "options",
    [
        {"days": 0},
        {"days": -1},
        {"days": 3651},
        {"days": True},
        {"days": "1.5"},
        {"common_name": ""},
        {"common_name": "bad\nname"},
        {"common_name": "x" * 65},
        {"sans": ""},
        {"sans": "bad/name"},
        {"sans": "a..test"},
        {"sans": ["x"]},
    ],
)
def test_invalid_local_options_leave_files_untouched(material, monkeypatch, options):
    client, body = agent(material, monkeypatch)
    before = (material[0] / "server.pem").read_bytes()
    result = client.post("/certificates", headers=AUTH, json={**body, **options})
    assert result.status_code == 400
    assert before == (material[0] / "server.pem").read_bytes()


def test_lifetime_capped_and_legacy_identity_preserved(material):
    directory, ca, server, _ = material
    result = certificate_changes(
        (directory / "ca.pem").read_bytes(),
        (directory / "ca.key").read_bytes(),
        (directory / "server.pem").read_bytes(),
        None,
        PASSWORD,
        "renew-server",
        certificate_options({"days": 3650}),
    )
    cert = x509.load_pem_x509_certificate(result["server.pem"].encode())
    assert cert.not_valid_after_utc == ca.not_valid_after_utc
    assert cert.subject == server.subject
    assert (
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        == server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    )


def test_ca_agent_issuance_inventory_revocation_and_auth(tmp_path, monkeypatch, material):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("STEP_CA_ROOT", str(material[0] / "ca.pem"))
    calls = []

    def sign(request, output, days):
        calls.append((request.read_text(), days))
        output.write_bytes(material[2].public_bytes(PEM))

    monkeypatch.setattr("netadmin.agents.ca.sign_csr", sign)
    monkeypatch.setattr(
        "netadmin.agents.ca.revoke_certificate",
        lambda serial, reason: calls.append((serial, reason)),
    )
    client = create_ca_agent().test_client()
    assert client.get("/certificates").status_code == 401
    assert client.post("/certificates", headers=AUTH, json={"csr": csr(ca=True)}).status_code == 400
    assert client.post("/certificates", headers=AUTH, json={"csr": "invalid"}).status_code == 400
    result = client.post("/certificates", headers=AUTH, json={"csr": csr(), "days": 365})
    assert result.status_code == 201
    identifier = result.json["id"]
    assert calls[0][1] == 365
    assert client.get("/certificates", headers=AUTH).json["certificates"][0]["id"] == identifier
    assert "PRIVATE KEY" not in client.get(f"/certificates/{identifier}", headers=AUTH).text
    assert client.get("/certificates/root", headers=AUTH).status_code == 200
    assert client.get("/certificates/invalid", headers=AUTH).status_code == 404
    assert (
        client.post(
            f"/certificates/{identifier}/revoke", headers=AUTH, json={"reason": 8}
        ).status_code
        == 400
    )
    for _ in range(2):
        assert (
            client.post(
                f"/certificates/{identifier}/revoke", headers=AUTH, json={"reason": 1}
            ).status_code
            == 200
        )
    assert calls[-1] == (material[2].serial_number, 1)
    assert len(calls) == 2
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.post("/certificates", headers=AUTH, json={"csr": csr()}).status_code == 403


def test_revocation_by_current_hex_serial_is_validated_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    calls = []
    monkeypatch.setattr(
        "netadmin.agents.ca.revoke_certificate",
        lambda serial, reason: calls.append((serial, reason)),
    )
    client = create_ca_agent().test_client()
    for serial in ("", "../x", "-1", "0", 123, "f" * 41):
        assert client.post("/revoke", headers=AUTH, json={"serial": serial}).status_code == 400
    for _ in range(2):
        response = client.post("/revoke", headers=AUTH, json={"serial": "abc123", "reason": 1})
        assert response.status_code == 200
    assert calls == [(int("abc123", 16), 1)]
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.post("/revoke", headers=AUTH, json={"serial": "123"}).status_code == 403


def test_csr_validation_and_server_chain(material):
    assert validate_csr(csr()).is_signature_valid
    with pytest.raises(ValueError):
        validate_csr(csr(ca=True))
    with pytest.raises(ValueError):
        validate_csr("x" * 33000)
    directory, ca, server, key = material
    assert validate_server_chain(server.public_bytes(PEM), ca.public_bytes(PEM))[0] == server
    wrong = issue_certificate(ca, ec.generate_private_key(ec.SECP256R1()), ca, key, is_ca=True)
    with pytest.raises((ValueError, InvalidSignature)):
        validate_server_chain(server.public_bytes(PEM), wrong.public_bytes(PEM))
    assert not radius_renewal.renewal_due((directory / "server.pem").read_bytes())


def test_step_enrolment_and_renewal_preserve_key_and_validate_before_install(material, monkeypatch):
    directory, ca, server, key = material
    monkeypatch.setenv("STEP_CA_ROOT", str(directory / "ca.pem"))

    def issue(_path, payload, **_kwargs):
        request = validate_csr(payload["csr"])
        cert = (
            x509.CertificateBuilder()
            .subject_name(request.subject)
            .issuer_name(ca.subject)
            .public_key(request.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(
                request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(key, hashes.SHA256())
        )
        return {"pem": cert.public_bytes(PEM).decode()}

    monkeypatch.setattr(radius_step_ca, "_client", lambda: SimpleNamespace(post=issue))
    with pytest.raises(ValueError):
        radius_step_ca.changes(directory, PASSWORD, {"action": "enroll-step-ca"})
    files = radius_step_ca.changes(
        directory, PASSWORD, {"action": "enroll-step-ca", "confirmation": "STEP CA"}
    )
    bundle = files["server.pem"].encode()
    assert radius_step_ca.managed(bundle)
    (directory / "server.pem").write_bytes(bundle)
    cert = x509.load_pem_x509_certificate(bundle)

    def renew(source, keyfile, output, password):
        assert password.read_bytes() == PASSWORD
        assert x509.load_pem_x509_certificate(source.read_bytes()) == cert
        assert key_matches(cert, load_signing_key(keyfile.read_bytes(), PASSWORD))
        replacement = issue_certificate(cert, load_signing_key(bundle, PASSWORD), ca, key)
        output.write_bytes(replacement.public_bytes(PEM))

    monkeypatch.setattr(radius_step_ca, "renew_certificate", renew)
    renewed = radius_step_ca.changes(directory, PASSWORD, {"action": "renew-server"})
    assert key_matches(
        x509.load_pem_x509_certificate(renewed["server.pem"].encode()),
        load_signing_key(bundle, PASSWORD),
    )
    assert (directory / "server.pem").read_bytes() == bundle  # Preparation never activates files.
    monkeypatch.setattr(
        radius_step_ca,
        "renew_certificate",
        lambda source, keyfile, output, password: output.write_bytes(server.public_bytes(PEM)),
    )
    with pytest.raises(ValueError):
        radius_step_ca.changes(directory, PASSWORD, {"action": "renew-server"})


def test_renewal_worker_checks_mode_readonly_due_and_activation(material, monkeypatch):
    client, _ = agent(material, monkeypatch)
    monkeypatch.setenv("RADIUS_CERT_BACKEND", "step-ca")
    monkeypatch.setenv("RADIUS_CERT_AUTO_RENEW", "true")
    monkeypatch.setenv("STEP_CA_ROOT", str(material[0] / "ca.pem"))
    monkeypatch.setattr(radius_renewal, "managed", lambda data: True)
    monkeypatch.setattr(radius_renewal, "renewal_due", lambda data: True)
    monkeypatch.setattr(radius_renewal, "changes", lambda *args: {"server.pem": "staged"})
    installed = []
    monkeypatch.setattr(radius_renewal, "_install", lambda changes: installed.append(changes))
    with client.application.app_context():
        assert radius_renewal.renew_once()
        assert installed == [{"server.pem": "staged"}]
        monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
        assert not radius_renewal.renew_once()
        monkeypatch.delenv("NETADMIN_AGENT_READ_ONLY")
        monkeypatch.setattr(radius_renewal, "renewal_due", lambda data: False)
        assert not radius_renewal.renew_once()


def test_ca_ui_admin_csrf_and_public_download(tmp_path, monkeypatch):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], ca_agent_url="https://ca-agent:8084"
    )
    calls = []
    remote = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: {"certificates": []} if path == "certificates" else {"pem": "PUBLIC"},
        post=lambda path, payload, **kwargs: calls.append((path, payload)) or {"id": "1" * 32},
    )
    monkeypatch.setattr("netadmin.ca_web._client", lambda: remote)
    assert client.get("/certificates").status_code == 200
    preview = client.post("/certificates/inspect", data={"csr": csr(), "days": 30})
    assert preview.status_code == 200
    assert "CN=radius.test" in preview.text
    assert "radius.test" in preview.text
    assert not calls

    assert client.post("/certificates", data={"csr": csr()}).status_code == 400
    assert (
        client.post("/certificates", data={"csr": csr(), "days": 365, "confirm": "yes"}).status_code
        == 302
    )
    assert calls[-1][0] == "certificates"
    assert client.get("/certificates/root/download").text == "PUBLIC"
    assert (
        client.post(
            "/certificates/" + "1" * 32 + "/revoke", data={"confirm": "yes", "reason": 1}
        ).status_code
        == 302
    )
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/certificates", data={"confirm": "yes"}).status_code == 400
    token = app.extensions["netadmin_store"].create_session("standard", "standard", 60)
    client.set_cookie("netadmin_session", token)
    assert client.get("/certificates").status_code == 403
