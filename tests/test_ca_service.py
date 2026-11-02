"""Synthetic CSR policy, CA agent, local identity and staged renewal regression tests."""

import ipaddress
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


@pytest.fixture(autouse=True)
def ca_configuration(monkeypatch, tmp_path, material):
    """Supply synthetic local signing configuration even when the CLI is stubbed."""
    secret = tmp_path / "provisioner-password"
    secret.write_text("synthetic-password")
    monkeypatch.setenv("STEP_CA_URL", "https://ca.test:9000")
    monkeypatch.setenv("STEP_CA_PROVISIONER", "synthetic")
    monkeypatch.setenv("STEP_CA_ROOT", str(material[0] / "ca.pem"))
    monkeypatch.setenv("STEP_CA_PASSWORD_FILE", str(secret))


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


@pytest.mark.parametrize(
    "action, days", [("create-server", 365), ("renew-server", 365), ("renew-server", 30)]
)
def test_local_custom_identity_and_validity(material, monkeypatch, action, days):
    client, body = agent(material, monkeypatch)
    result = client.post(
        "/certificates",
        headers=AUTH,
        json={
            **body,
            "action": action,
            "common_name": "new.example.test",
            "sans": "new.example.test,192.0.2.15,2001:db8::1",
            "days": str(days),
        },
    )
    assert result.status_code == 200, result.json
    cert = x509.load_pem_x509_certificate((material[0] / "server.pem").read_bytes())
    cert.verify_directly_issued_by(material[1])
    assert (
        ExtendedKeyUsageOID.SERVER_AUTH
        in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "new.example.test"
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(name.value) for name in names] == ["new.example.test", "192.0.2.15", "2001:db8::1"]
    assert (
        timedelta(days=days)
        <= cert.not_valid_after_utc - cert.not_valid_before_utc
        < timedelta(days=days + 1)
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
        request_csr = validate_csr(request.read_text())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(request_csr.subject)
            .issuer_name(material[1].subject)
            .public_key(request_csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=days))
            .add_extension(
                request_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                False,
            )
            .sign(material[3], hashes.SHA256())
        )
        output.write_bytes(certificate.public_bytes(PEM))

    monkeypatch.setattr("netadmin.agents.ca.sign_csr", sign)
    monkeypatch.setattr(
        "netadmin.agents.ca.revoke_certificate",
        lambda serial, reason: calls.append((serial, reason)),
    )
    client = create_ca_agent().test_client()
    assert client.get("/certificates").status_code == 401
    assert client.post("/certificates", headers=AUTH, json={"csr": csr(ca=True)}).status_code == 400
    assert client.post("/certificates", headers=AUTH, json={"csr": "invalid"}).status_code == 400
    request_pem = csr()
    result = client.post("/certificates", headers=AUTH, json={"csr": request_pem, "days": 365})
    issued = x509.load_pem_x509_certificate(result.json["pem"].encode())
    from netadmin.services.step_ca import issued_matches_csr

    assert issued_matches_csr(issued.public_bytes(PEM), validate_csr(request_pem)) == issued
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
    assert calls[-1] == (issued.serial_number, 1)
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
    ca_request = csr(ca=True)
    with pytest.raises(ValueError):
        validate_csr(ca_request)
    with pytest.raises(ValueError):
        validate_csr("x" * 33000)
    directory, ca, server, key = material
    assert validate_server_chain(server.public_bytes(PEM), ca.public_bytes(PEM))[0] == server
    wrong = issue_certificate(ca, ec.generate_private_key(ec.SECP256R1()), ca, key, is_ca=True)
    server_pem, wrong_pem = server.public_bytes(PEM), wrong.public_bytes(PEM)
    with pytest.raises((ValueError, InvalidSignature)):
        validate_server_chain(server_pem, wrong_pem)
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
        assert password == PASSWORD
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


def test_tampered_csr_signature_is_rejected():
    from cryptography.hazmat.primitives.serialization import Encoding

    request = x509.load_pem_x509_csr(csr().encode())
    der = bytearray(request.public_bytes(Encoding.DER))
    der[-1] ^= 1
    tampered = x509.load_der_x509_csr(bytes(der)).public_bytes(PEM).decode()
    with pytest.raises(ValueError, match="signature"):
        validate_csr(tampered)


def test_issuance_retries_recover_complete_output_without_resigning(
    tmp_path, monkeypatch, material
):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    calls = []
    request_pem = csr()
    request = validate_csr(request_pem)
    cert = (
        x509.CertificateBuilder()
        .subject_name(request.subject)
        .issuer_name(material[1].subject)
        .public_key(request.public_key())
        .serial_number(1234)
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=10))
        .add_extension(
            request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False
        )
        .sign(material[3], hashes.SHA256())
    )

    def sign(_request, output, _days):
        calls.append(output)
        output.write_bytes(cert.public_bytes(PEM))

    monkeypatch.setattr("netadmin.agents.ca.sign_csr", sign)
    client = create_ca_agent().test_client()
    payload = {"csr": request_pem, "request_id": "a" * 32}
    monkeypatch.delenv("STEP_CA_URL")
    assert client.post("/certificates", json=payload, headers=AUTH).status_code == 502
    assert not list((tmp_path / "ledger").glob("*/attempted"))
    monkeypatch.setenv("STEP_CA_URL", "https://ca.test:9000")
    first = client.post("/certificates", json=payload, headers=AUTH)
    assert first.status_code == 201
    second = client.post("/certificates", json=payload, headers=AUTH)
    assert second.json == first.json
    assert len(calls) == 1
    directory = tmp_path / "ledger" / first.json["id"]
    (directory / "certificate.pem").rename(directory / "signing.pem")
    recovered = client.post("/certificates", json=payload, headers=AUTH)
    assert recovered.json == first.json
    assert len(calls) == 1
    assert (
        client.post("/certificates", json={**payload, "days": 1}, headers=AUTH).status_code == 409
    )


def test_partial_and_mismatched_signatures_never_poison_inventory(
    tmp_path, monkeypatch, material, caplog
):
    import subprocess

    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    calls = []

    def fail(_request, output, _days):
        calls.append(output)
        output.write_bytes(b"partial certificate")
        raise subprocess.CalledProcessError(1, "synthetic", stderr="secret must never be logged")

    monkeypatch.setattr("netadmin.agents.ca.sign_csr", fail)
    client = create_ca_agent().test_client()
    payload = {"csr": csr()}
    for _ in range(2):
        assert client.post("/certificates", json=payload, headers=AUTH).status_code == 502
    assert len(calls) == 1
    assert "secret must never be logged" not in caplog.text
    assert client.get("/certificates", headers=AUTH).json["certificates"] == []
    monkeypatch.setattr(
        "netadmin.agents.ca.sign_csr",
        lambda request, output, days: output.write_bytes(material[2].public_bytes(PEM)),
    )
    assert client.post("/certificates", json={"csr": csr()}, headers=AUTH).status_code == 502
    assert client.get("/certificates", headers=AUTH).json["certificates"] == []
    bad = tmp_path / "ledger" / ("f" * 32)
    bad.mkdir()
    (bad / "certificate.pem").write_bytes(b"partial legacy certificate")
    assert client.get("/certificates", headers=AUTH).status_code == 200


def test_crl_configuration_errors_return_controlled_response(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    client = create_ca_agent().test_client()
    for url in (None, "http://insecure.test"):
        if url is None:
            monkeypatch.delenv("STEP_CA_URL", raising=False)
        else:
            monkeypatch.setenv("STEP_CA_URL", url)
        assert client.get("/crl", headers=AUTH).status_code == 502


def test_renewal_password_uses_stdin_not_a_file(monkeypatch):
    from pathlib import Path

    from netadmin.services.step_ca import renew_certificate, run_step

    calls = []
    monkeypatch.setenv("STEP_CA_URL", "https://ca.test:9000")
    monkeypatch.setattr(
        "netadmin.services.step_ca.subprocess.run",
        lambda args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(stdout="ok"),
    )
    renew_certificate(Path("certificate"), Path("key"), Path("renewed"), b"synthetic-password")
    args, options = calls[0]
    assert args[args.index("--password-file") + 1] == "/dev/stdin"
    assert "synthetic-password" not in args
    assert options["input"] == "synthetic-password"
    assert options["timeout"] == 20
    run_step(["ca", "health"])
    assert calls[-1][1]["input"] is None


def test_already_revoked_serial_repairs_local_state(tmp_path, monkeypatch, material):
    import subprocess

    from netadmin.services import step_ca
    from netadmin.services.radius_certificates import issue_crl

    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("STEP_CA_URL", "https://ca.test")
    monkeypatch.setenv("STEP_CA_PROVISIONER", "synthetic")

    def run(arguments, **kwargs):
        if arguments[1] == "token":
            return "synthetic-token"
        raise subprocess.CalledProcessError(1, "step", stderr="authority rejected request")

    monkeypatch.setattr(step_ca, "run_step", run)
    crl = issue_crl(material[1], material[3], None, material[2])
    monkeypatch.setattr(step_ca, "fetch_crl", lambda: crl)
    client = create_ca_agent().test_client()
    serial = format(material[2].serial_number, "x")
    result = client.post("/revoke", json={"serial": serial, "reason": 1}, headers=AUTH)
    assert result.status_code == 200
    assert (tmp_path / "ledger" / "revocations" / serial).read_text() == "1"
    assert not (tmp_path / "ledger" / "revocations" / (serial + ".pending")).exists()


def test_unavailable_ca_and_unknown_download_are_controlled(tmp_path, monkeypatch):
    import httpx

    _, client = admin_client(tmp_path)

    def get(path):
        if path == "certificates/missing":
            response = httpx.Response(404, request=httpx.Request("GET", "https://ca.test"))
            raise httpx.HTTPStatusError("missing", request=response.request, response=response)
        raise httpx.ConnectError("synthetic outage")

    monkeypatch.setattr("netadmin.ca_web._client", lambda: SimpleNamespace(get=get))
    assert client.post("/certificates/inspect", data={"csr": csr()}).status_code == 502
    assert client.get("/certificates/missing/download").status_code == 404
    assert client.get("/certificates/root/download").status_code == 502


def test_compose_limits_ca_exposure_and_shares_radius_pid_namespace():
    from pathlib import Path

    import yaml

    compose = yaml.safe_load(Path("docker-compose.step-ca.yml").read_text())
    assert compose["services"]["step-ca"]["ports"] == ["127.0.0.1:9000:9000"]
    assert compose["services"]["radius-renewal"]["pid"] == "service:radius"
    radius = compose["services"]["radius-agent"]
    assert radius["environment"]["RADIUS_CA_AGENT_URL"] == "https://ca-agent:8084"
    assert "./pki/ca-agent-client:/ca-agent-client:ro" in radius["volumes"]
    assert "./step-ca/certs/root_ca.crt:/trust/root_ca.crt:ro" in radius["volumes"]


def test_uncertain_issuance_is_not_automatically_repeated(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    calls = []

    def timeout(*args):
        calls.append(args)
        raise subprocess.TimeoutExpired("step", 20)

    monkeypatch.setattr("netadmin.agents.ca.sign_csr", timeout)
    client = create_ca_agent().test_client()
    payload = {"csr": csr()}
    assert client.post("/certificates", json=payload, headers=AUTH).status_code == 502
    assert client.post("/certificates", json=payload, headers=AUTH).status_code == 409
    assert len(calls) == 1


def test_status_waits_for_certificate_transaction_lock(material, monkeypatch):
    import fcntl
    from threading import Event, Thread

    client, _ = agent(material, monkeypatch)
    started, read = Event(), Event()
    results = []

    def inventory():
        read.set()
        return {"available": True}

    monkeypatch.setattr("netadmin.agents.radius_certificates._inventory", inventory)

    def status():
        started.set()
        results.append(client.application.test_client().get("/certificates", headers=AUTH))

    with (material[0] / ".netadmin-cert-lock").open("a") as writer:
        fcntl.flock(writer, fcntl.LOCK_EX)
        thread = Thread(target=status)
        thread.start()
        assert started.wait(1)
        assert not read.wait(0.1)
        fcntl.flock(writer, fcntl.LOCK_UN)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert results[0].json == {"available": True}


def test_issuance_request_id_cannot_escape_agent_state(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    client = create_ca_agent().test_client()
    pem = csr()
    for identifier in ("../" * 10 + "aa", "/" + "a" * 31, "a" * 31 + ".", "A" * 32):
        result = client.post(
            "/certificates", headers=AUTH, json={"csr": pem, "request_id": identifier}
        )
        assert result.status_code == 400
    assert list((tmp_path / "ledger").iterdir()) == []


def test_ca_missing_configuration_returns_502_on_revocation(tmp_path, monkeypatch, material):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.delenv("STEP_CA_PROVISIONER")
    client = create_ca_agent().test_client()
    directory = tmp_path / "ledger" / ("a" * 32)
    directory.mkdir()
    (directory / "certificate.pem").write_bytes(material[2].public_bytes(PEM))
    assert (
        client.post("/certificates/" + "a" * 32 + "/revoke", json={}, headers=AUTH).status_code
        == 502
    )
    assert client.post("/revoke", json={"serial": "1234"}, headers=AUTH).status_code == 502


def test_durable_ca_records_sync_file_then_parent(tmp_path, monkeypatch):
    import os
    import stat

    from netadmin.agents.ca import _durable_write

    original = os.fsync
    synced = []

    def sync(descriptor):
        synced.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
        original(descriptor)

    monkeypatch.setattr("netadmin.agents.ca.os.fsync", sync)
    target = tmp_path / "attempted"
    _durable_write(target, "1")
    assert synced == ["file", "directory"]
    assert target.read_text() == "1"


def test_inventory_pages_preserve_access_to_every_record(tmp_path, monkeypatch, material):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    client = create_ca_agent().test_client()
    for index in range(105):
        directory = tmp_path / "ledger" / format(index, "032x")
        directory.mkdir()
        (directory / "certificate.pem").write_bytes(material[2].public_bytes(PEM))
    first = client.get("/certificates", headers=AUTH).json
    assert len(first["certificates"]) == 100
    second = client.get("/certificates?after=" + first["next_cursor"], headers=AUTH).json
    assert len(second["certificates"]) == 5
    assert second["next_cursor"] is None
    ids = [record["id"] for record in first["certificates"] + second["certificates"]]
    assert len(set(ids)) == 105
    assert client.get("/certificates?after=../", headers=AUTH).status_code == 400


def test_timed_out_radius_operation_is_audited_as_unknown(tmp_path, monkeypatch):
    import httpx

    app, client = admin_client(tmp_path)

    def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("synthetic timeout")

    app.extensions["netadmin_radius"] = SimpleNamespace(read_only=lambda: False, post=timeout)
    response = client.post(
        "/radius/certificates", data={"action": "enroll-step-ca", "confirm": "yes"}
    )
    assert response.status_code == 302
    event = app.extensions["netadmin_store"].recent_audit()[0]
    assert event["success"] is None
    assert "Unknown" in client.get("/audit").text


def test_unsupported_sans_are_displayed_but_not_prefilled_for_editing(material, tmp_path):
    from netadmin.services.radius_certificates import certificate_info

    _, ca, server, ca_key = material
    key = ec.generate_private_key(ec.SECP256R1())
    names = x509.SubjectAlternativeName(
        [
            x509.DNSName("radius.test"),
            x509.UniformResourceIdentifier("spiffe://example.test/radius"),
            x509.RFC822Name("radius@example.test"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(server.subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(123)
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(names, True)
        .sign(ca_key, hashes.SHA256())
    )
    metadata = certificate_info(certificate)
    assert metadata["editable_sans"] == "radius.test"
    assert metadata["unsupported_sans"]
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: {
            "available": True,
            "can_manage": True,
            "has_crl": False,
            "ca": certificate_info(ca),
            "server": metadata,
        },
    )
    page = client.get("/radius/certificates")
    assert "Renewal preserves all existing SANs" in page.text
    assert 'maxlength="8192" disabled' in page.text
    renewed = issue_certificate(certificate, key, ca, ca_key, options={"days": 1})
    assert renewed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == names


def test_empty_subject_replacement_san_remains_critical(material):
    _, ca, _, ca_key = material
    key = ec.generate_private_key(ec.SECP256R1())
    names = x509.SubjectAlternativeName([x509.DNSName("radius.test")])
    original = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(124)
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(names, True)
        .sign(ca_key, hashes.SHA256())
    )
    renewed = issue_certificate(original, key, ca, ca_key, options={"sans": names})
    assert renewed.extensions.get_extension_for_class(x509.SubjectAlternativeName).critical


@pytest.mark.parametrize(
    "path",
    ["/certificates", "/certificates/revoke-serial", "/certificates/" + "a" * 32 + "/revoke"],
)
def test_timed_out_ca_operations_are_audited_as_unknown(tmp_path, monkeypatch, path):
    import httpx

    app, client = admin_client(tmp_path)

    def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("synthetic timeout")

    monkeypatch.setattr(
        "netadmin.ca_web._client", lambda: SimpleNamespace(read_only=lambda: False, post=timeout)
    )
    expected = 202 if path == "/certificates" else 302
    assert client.post(path, data={"confirm": "yes", "serial": "abc123"}).status_code == expected
    assert app.extensions["netadmin_store"].recent_audit()[0]["success"] is None


@pytest.mark.parametrize(
    "options", [{"common_name": "new.test"}, {"sans": "new.test"}, {"days": 30}]
)
def test_step_ca_renewal_rejects_identity_and_lifetime_overrides(material, monkeypatch, options):
    client, body = agent(material, monkeypatch)
    monkeypatch.setenv("RADIUS_CERT_BACKEND", "step-ca")
    before = (material[0] / "server.pem").read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError("Renewal must not run when overrides were supplied")

    monkeypatch.setattr(radius_step_ca, "changes", forbidden)
    result = client.post(
        "/certificates", json={**body, "action": "renew-server", **options}, headers=AUTH
    )
    assert result.status_code == 409
    assert (material[0] / "server.pem").read_bytes() == before


@pytest.mark.parametrize(
    "error_name", ["ReadTimeout", "ReadError", "RemoteProtocolError", "WriteError", "ValueError"]
)
def test_uncertain_issuance_retries_keep_request_id_and_audit_reference(
    tmp_path, monkeypatch, error_name
):
    import json
    import re

    import httpx

    app, client = admin_client(tmp_path)
    calls = []
    operation_id = "d" * 32
    pem = csr()

    def post(path, payload, **kwargs):
        calls.append(payload.copy())
        if len(calls) == 1:
            error_class = ValueError if error_name == "ValueError" else getattr(httpx, error_name)
            raise error_class("response lost after issuance")
        return {"id": operation_id, "certificate": {"serial": "beef"}}

    remote = SimpleNamespace(
        read_only=lambda: False, post=post, get=lambda path: {"certificates": []}
    )
    monkeypatch.setattr("netadmin.ca_web._client", lambda: remote)
    payload = {"csr": pem, "days": "30", "request_id": operation_id, "confirm": "yes"}
    uncertain = client.post("/certificates", data=payload)
    assert uncertain.status_code == 202
    assert "Retry same request" in uncertain.text
    assert "not refreshed" in uncertain.text
    saved_id = re.search(r'name="request_id" value="([0-9a-f]{32})"', uncertain.text)[1]
    assert saved_id == operation_id
    inventory = client.get("/certificates", query_string={"request_id": saved_id, "days": "30"})
    assert f'name="request_id" value="{operation_id}"' in inventory.text
    assert 'value="30"' in inventory.text
    assert pem in uncertain.text
    event = app.extensions["netadmin_store"].recent_audit()[0]
    assert event["success"] is None
    assert event["target"] == operation_id
    assert json.loads(event["details"])["request_id"] == operation_id
    inspected = client.post("/certificates/inspect", data=payload)
    assert f'value="{operation_id}"' in inspected.text
    assert client.post("/certificates", data={**payload, "request_id": saved_id}).status_code == 302
    assert {call["request_id"] for call in calls} == {operation_id}
    success = app.extensions["netadmin_store"].recent_audit()[0]
    assert success["success"] == 1
    assert success["target"] == "beef"
    assert json.loads(success["details"])["request_id"] == operation_id


@pytest.mark.parametrize("status,outcome", [(409, "unknown"), (502, None)])
def test_uncertain_agent_response_preserves_the_issuance_form(
    tmp_path, monkeypatch, status, outcome
):
    import httpx

    app, client = admin_client(tmp_path)

    def post(*args, **kwargs):
        response = httpx.Response(
            status,
            json={"outcome": outcome},
            request=httpx.Request("POST", "https://ca.test/certificates"),
        )
        raise httpx.HTTPStatusError("uncertain", request=response.request, response=response)

    monkeypatch.setattr(
        "netadmin.ca_web._client", lambda: SimpleNamespace(read_only=lambda: False, post=post)
    )
    result = client.post(
        "/certificates", data={"csr": csr(), "request_id": "e" * 32, "confirm": "yes"}
    )
    assert result.status_code == 202
    assert 'value="' + "e" * 32 + '"' in result.text
    assert app.extensions["netadmin_store"].recent_audit()[0]["success"] is None


def test_revocation_audit_identifies_record_and_serial(tmp_path, monkeypatch):
    import json

    app, client = admin_client(tmp_path)
    monkeypatch.setattr(
        "netadmin.ca_web._client",
        lambda: SimpleNamespace(
            read_only=lambda: False, post=lambda *a, **k: {"status": "revoked"}
        ),
    )
    identifier = "a" * 32
    assert (
        client.post(f"/certificates/{identifier}/revoke", data={"confirm": "yes"}).status_code
        == 302
    )
    by_record = app.extensions["netadmin_store"].recent_audit()[0]
    assert by_record["target"] == identifier
    assert json.loads(by_record["details"])["certificate_id"] == identifier
    assert (
        client.post(
            "/certificates/revoke-serial", data={"confirm": "yes", "serial": "abc123"}
        ).status_code
        == 302
    )
    by_serial = app.extensions["netadmin_store"].recent_audit()[0]
    assert by_serial["target"] == "abc123"
    assert json.loads(by_serial["details"])["serial"] == "abc123"


@pytest.mark.parametrize("can_sign", [False, True])
def test_issuer_key_usage_must_allow_certificate_signing(material, can_sign):
    _, ca, server, key = material
    issuer = (
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(777)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=can_sign,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    server_pem, issuer_pem = server.public_bytes(PEM), issuer.public_bytes(PEM)
    if can_sign:
        assert validate_server_chain(server_pem, issuer_pem)[-1] == issuer
    else:
        with pytest.raises(ValueError, match="cannot sign"):
            validate_server_chain(server_pem, issuer_pem)


def test_step_enrolment_warns_about_removing_other_san_types(tmp_path, material):
    from netadmin.services.radius_certificates import certificate_info

    app, client = admin_client(tmp_path)
    status = {
        "available": True,
        "can_manage": True,
        "backend": "step-ca",
        "auto_renew": True,
        "enrolled": False,
        "has_crl": False,
        "ca": certificate_info(material[1]),
        "server": {**certificate_info(material[2]), "unsupported_sans": True},
    }
    app.extensions["netadmin_radius"] = SimpleNamespace(
        read_only=lambda: False, get=lambda path: status
    )
    page = client.get("/radius/certificates")
    assert page.status_code == 200
    assert "Enrolment removes the current URI, email" in page.text


def test_non_ascii_csr_is_a_controlled_validation_error(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    remote = create_ca_agent().test_client()
    assert remote.post("/certificates", headers=AUTH, json={"csr": "invalid-é"}).status_code == 400
    _, client = admin_client(tmp_path)
    monkeypatch.setattr("netadmin.ca_web._client", lambda: SimpleNamespace())
    assert client.post("/certificates/inspect", data={"csr": "invalid-é"}).status_code == 302


def test_certificate_navigation_stays_active_on_inspection(tmp_path, monkeypatch):
    import re

    app, client = admin_client(tmp_path)
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], ca_agent_url="https://ca-agent:8084"
    )
    monkeypatch.setattr(
        "netadmin.ca_web._client",
        lambda: SimpleNamespace(read_only=lambda: False, get=lambda path: {"certificates": []}),
    )
    response = client.post("/certificates/inspect", data={"csr": csr()})
    assert response.status_code == 200
    assert re.search(
        r'class="section-link active" href="/certificates"\s+aria-current="page"', response.text
    )


def test_issued_sans_must_match_csr_even_when_key_and_subject_match(material):
    from netadmin.services.step_ca import issued_matches_csr

    key = ec.generate_private_key(ec.SECP256R1())
    request = validate_csr(csr(key))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(request.subject)
        .issuer_name(material[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("other.test")]), False)
        .sign(material[3], hashes.SHA256())
    )
    pem = certificate.public_bytes(PEM)
    with pytest.raises(ValueError, match="SANs do not match"):
        issued_matches_csr(pem, request)


def test_new_step_ca_leaf_requires_signing_key_usage(material, monkeypatch):
    directory, ca, previous, ca_key = material
    monkeypatch.setenv("STEP_CA_ROOT", str(directory / "ca.pem"))
    key = load_signing_key((directory / "server.pem").read_bytes(), PASSWORD)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(previous.subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            previous.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(False, False, True, False, False, False, False, False, False), True
        )
        .sign(ca_key, hashes.SHA256())
    )
    monkeypatch.setattr(
        radius_step_ca,
        "renew_certificate",
        lambda source, keyfile, output, password: output.write_bytes(certificate.public_bytes(PEM)),
    )
    original = (directory / "server.pem").read_bytes()
    with pytest.raises(ValueError, match="digital signatures"):
        radius_step_ca.changes(directory, PASSWORD, {"action": "renew-server"})
    assert (directory / "server.pem").read_bytes() == original


@pytest.mark.parametrize(
    "url", ["http://agent", "https://user:password@agent", "https://agent:99999", "https://agent:0"]
)
def test_agent_client_rejects_unsafe_endpoint_before_network(url):
    from netadmin.services.agents import AgentClient

    with pytest.raises(ValueError):
        AgentClient(url, "synthetic")


@pytest.mark.parametrize(
    "url", ["https://step-ca:99999", "https://step-ca:0", "https://step-ca:invalid"]
)
def test_invalid_ca_port_does_not_create_operation_state(tmp_path, monkeypatch, url):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("STEP_CA_URL", url)
    client = create_ca_agent().test_client()
    assert client.post("/certificates", headers=AUTH, json={"csr": csr()}).status_code == 502
    assert list((tmp_path / "ledger").iterdir()) == []


@pytest.mark.parametrize(
    "common_name,name",
    [
        ("radius.test", x509.DNSName("radius.test")),
        ("2001:db8::1", x509.IPAddress(ipaddress.ip_address("2001:db8:0:0::1"))),
        ("person@example.test", x509.RFC822Name("person@example.test")),
        (
            "spiffe://example.test/Server",
            x509.UniformResourceIdentifier("spiffe://example.test/Server"),
        ),
    ],
)
def test_sanless_csr_only_allows_cn_derived_san(material, common_name, name):
    from netadmin.services.step_ca import issued_matches_csr

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    request = (
        x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(material[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    )
    without_sans = builder.sign(material[3], hashes.SHA256())
    assert issued_matches_csr(without_sans.public_bytes(PEM), request) == without_sans
    allowed = builder.add_extension(x509.SubjectAlternativeName([name]), False).sign(
        material[3], hashes.SHA256()
    )
    assert issued_matches_csr(allowed.public_bytes(PEM), request) == allowed
    extra = builder.add_extension(
        x509.SubjectAlternativeName([name, x509.DNSName("extra.test")]), False
    ).sign(material[3], hashes.SHA256())
    pem = extra.public_bytes(PEM)
    with pytest.raises(ValueError, match="SANs do not match"):
        issued_matches_csr(pem, request)


@pytest.mark.parametrize("identifier", ["..", "%2e%2e", "abc%3Fignored", "a" * 31 + "%25"])
def test_certificate_routes_reject_noncanonical_ids_before_calling_agent(
    tmp_path, monkeypatch, identifier
):
    _, client = admin_client(tmp_path)
    calls = []
    remote = SimpleNamespace(
        read_only=lambda: False,
        get=lambda *args: calls.append(args),
        post=lambda *args, **kwargs: calls.append(args),
    )
    monkeypatch.setattr("netadmin.ca_web._client", lambda: remote)
    assert client.get(f"/certificates/{identifier}/download").status_code == 404
    assert (
        client.post(f"/certificates/{identifier}/revoke", data={"confirm": "yes"}).status_code
        == 404
    )
    assert calls == []
