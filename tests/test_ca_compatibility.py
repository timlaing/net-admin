"""Existing CA interfaces retain authorization, error and certificate-validation contracts."""

import subprocess
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netadmin.services import step_ca
from tests.test_ca_runtime import TOKEN
from tests.test_ca_runtime_operations import configured as prepared_issuer  # noqa: F401
from tests.test_multi_service_ui import admin_client


@pytest.fixture
def issuer_state(request):
    return request.getfixturevalue("prepared_issuer")


@pytest.fixture
def legacy_web(tmp_path, monkeypatch):
    app, client = admin_client(tmp_path)
    state = app.extensions["netadmin_settings"]
    app.extensions["netadmin_settings"] = replace(state, ca_agent_url="https://legacy-ca.test:8084")
    calls = []
    remote = SimpleNamespace(
        read_only=lambda: False,
        get=lambda path: {"certificates": [], "pem": "synthetic-public-chain"},
        post=lambda path, payload, **kwargs: calls.append((path, payload, kwargs)),
    )
    monkeypatch.setattr("netadmin.ca_web._client", lambda: remote)
    return app, client, remote, calls


def test_legacy_ca_mutations_enforce_read_only_and_explicit_confirmation(legacy_web):
    _app, client, remote, calls = legacy_web
    paths = [
        "/certificates",
        "/certificates/" + "a" * 32 + "/revoke",
        "/certificates/revoke-serial",
    ]
    remote.read_only = lambda: True
    for path in paths:
        assert client.post(path, data={"confirm": "yes"}).status_code == 403
    remote.read_only = lambda: False
    for path in paths:
        assert client.post(path).status_code == 400
    assert not calls
    assert client.get("/certificates?request_id=invalid").status_code == 400


def test_legacy_ca_download_errors_preserve_status_and_backend_paths(legacy_web):
    _app, client, remote, _calls = legacy_web
    paths = []

    def get(path):
        paths.append(path)
        return {"pem": "public material"}

    remote.get = get
    assert client.get("/certificates/root/download").data == b"public material"
    assert client.get("/certificates/crl/download").data == b"public material"
    assert paths == ["certificates/root", "crl"]
    status = [404]

    def fail(path):
        response = httpx.Response(
            status[0], request=httpx.Request("GET", "https://legacy-ca.test/" + path)
        )
        response.raise_for_status()

    remote.get = fail
    assert client.get("/certificates/root/download").status_code == 404
    status[0] = 503
    assert client.get("/certificates/root/download").status_code == 502


def test_legacy_ca_preview_without_sans_and_nonjson_rejection(legacy_web):
    app, client, remote, _calls = legacy_web
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.test")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(Encoding.PEM).decode()
    page = client.post("/certificates/inspect", data={"csr": pem, "days": 1})
    assert page.status_code == 200 and b"No SANs requested" in page.data

    def reject(*_args, **_kwargs):
        response = httpx.Response(
            422,
            text="synthetic non-JSON error",
            request=httpx.Request("POST", "https://legacy-ca.test/certificates"),
        )
        response.raise_for_status()

    remote.post = reject
    result = client.post(
        "/certificates",
        data={"csr": pem, "days": 1, "confirm": "yes", "request_id": uuid.uuid4().hex},
    )
    assert result.status_code == 422
    assert b"synthetic non-JSON error" not in result.data
    assert b"agent rejected" in result.data

    def unavailable(*_args, **_kwargs):
        raise httpx.ConnectError("synthetic-private-connect-error")

    remote.post = unavailable
    assert (
        client.post(
            "/certificates",
            data={"csr": pem, "days": 1, "confirm": "yes", "request_id": uuid.uuid4().hex},
        ).status_code
        == 502
    )
    settings = app.extensions["netadmin_settings"]
    app.extensions["netadmin_settings"] = replace(settings, ca_management_token=TOKEN)
    assert client.get("/certificates").location.endswith("/certificates/authorities")


@pytest.mark.parametrize("kind", ["ed25519", "weak-rsa", "ca-signing-usage"])
def test_leaf_csr_validation_rejects_unsupported_keys_and_signing_privileges(kind):
    key = (
        ed25519.Ed25519PrivateKey.generate()
        if kind == "ed25519"
        else rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - weak-key rejection fixture
        if kind == "weak-rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.test")])
    )
    if kind == "ca-signing-usage":
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
    csr = builder.sign(key, None if kind == "ed25519" else hashes.SHA256())
    pem = csr.public_bytes(Encoding.PEM).decode()
    with pytest.raises(ValueError):
        step_ca.validate_csr(pem)


def test_step_signing_requires_readable_provisioner_credential_and_fixed_flags(
    issuer_state, monkeypatch, tmp_path
):
    state = issuer_state
    directory = state.store.directory(state.authority_id)
    monkeypatch.setenv("STEP_CA_URL", "https://ca.example.test:9100")
    monkeypatch.setenv("STEP_CA_ROOT", str(directory / "root.crt"))
    monkeypatch.setenv("STEP_CA_PROVISIONER", "netadmin")
    monkeypatch.setenv("STEP_CA_PASSWORD_FILE", str(tmp_path / "missing-password"))
    with pytest.raises(ValueError, match="unavailable"):
        step_ca.signing_configuration()
    monkeypatch.setenv("STEP_CA_PASSWORD_FILE", str(directory / "provisioner.password"))
    step_ca.signing_configuration()
    calls = []
    monkeypatch.setattr(step_ca, "run_step", lambda arguments: calls.append(arguments))
    request = tmp_path / "request.pem"
    output = tmp_path / "output.pem"
    step_ca.sign_csr(request, output, 30)
    assert calls == [
        [
            "ca",
            "sign",
            str(request),
            str(output),
            "--not-after",
            "720h",
            "--ca-url",
            "https://ca.example.test:9100",
            "--root",
            str(directory / "root.crt"),
            "--provisioner",
            "netadmin",
            "--provisioner-password-file",
            str(directory / "provisioner.password"),
        ]
    ]
    monkeypatch.setenv("STEP_CA_PROVISIONER", "--unsafe")
    with pytest.raises(ValueError, match="Invalid provisioner"):
        step_ca.provisioner_flags()


def server_certificate(
    state,
    *,
    expired=False,
    ca=False,
    usage=ExtendedKeyUsageOID.SERVER_AUTH,
    basic=True,
    name="device.test",
    public_key=None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(state.store.certificate(state.authority_id).subject)
        .public_key(public_key or key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage([usage]), False)
    )
    if basic:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True
        )
    return builder.sign(state.store.key(state.authority_id, {}), hashes.SHA384())


def test_server_chain_verifies_validity_ca_privileges_eku_and_missing_legacy_constraints(
    issuer_state,
):
    state = issuer_state
    root = state.store.certificate(state.root_id).public_bytes(Encoding.PEM)
    chain = state.store.chain(state.authority_id)
    valid = server_certificate(state, basic=False)
    assert step_ca.validate_server_chain(valid.public_bytes(Encoding.PEM) + chain, root)[0] == valid
    for certificate in (
        server_certificate(state, expired=True),
        server_certificate(state, ca=True),
        server_certificate(state, usage=ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        payload = certificate.public_bytes(Encoding.PEM) + chain
        with pytest.raises(ValueError):
            step_ca.validate_server_chain(payload, root)
    oversized_chain = valid.public_bytes(Encoding.PEM) * 7
    with pytest.raises(ValueError, match="Invalid server chain"):
        step_ca.validate_server_chain(oversized_chain, root)
    intermediate = state.store.certificate(state.authority_id)
    with pytest.raises(ValueError, match="constraints"):
        step_ca._validate_issuer(intermediate, 2)


def test_crl_fetch_pins_trust_and_failed_revoke_without_authoritative_entry_propagates(
    issuer_state, monkeypatch
):
    state = issuer_state
    directory = state.store.directory(state.authority_id)
    monkeypatch.setenv("STEP_CA_URL", "https://ca.example.test:9100")
    monkeypatch.setenv("STEP_CA_ROOT", str(directory / "root.crt"))
    monkeypatch.setenv("STEP_CA_PROVISIONER", "netadmin")
    monkeypatch.setenv("STEP_CA_PASSWORD_FILE", str(directory / "provisioner.password"))
    now = datetime.now(UTC)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(state.store.certificate(state.authority_id).subject)
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .sign(state.store.key(state.authority_id, {}), hashes.SHA384())
    )
    native_client = httpx.Client

    def response(request):
        assert str(request.url) == "https://ca.example.test:9100/1.0/crl"
        return httpx.Response(200, content=crl.public_bytes(Encoding.DER))

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["verify"].get_ca_certs(binary_form=True) == [
            state.store.certificate(state.root_id).public_bytes(Encoding.DER)
        ]
        return native_client(transport=httpx.MockTransport(response))

    monkeypatch.setattr(httpx, "Client", client)
    assert step_ca.fetch_crl() == crl

    def revoke(arguments):
        if arguments[:2] == ["ca", "token"]:
            return "synthetic-ephemeral-token"
        raise subprocess.CalledProcessError(1, arguments, stderr="synthetic unrelated failure")

    monkeypatch.setattr(step_ca, "run_step", revoke)
    with pytest.raises(subprocess.CalledProcessError):
        step_ca.revoke_certificate(123, 0)
    for error in (
        httpx.ReadError("synthetic-secret"),
        OSError("synthetic-secret"),
        KeyError("synthetic-secret"),
    ):
        assert "synthetic-secret" not in step_ca.failure_category(error)


def test_signed_response_must_preserve_csr_common_name(issuer_state):
    from tests.test_ca_runtime_operations import leaf_csr

    csr = leaf_csr()
    wrong = server_certificate(
        issuer_state, name="different.example.test", public_key=csr.public_key()
    )
    pem = wrong.public_bytes(Encoding.PEM)
    with pytest.raises(ValueError, match="common name"):
        step_ca.issued_matches_csr(pem, csr)
