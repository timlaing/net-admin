"""State corruption, partial writes, hierarchy capacity and recovery safeguards."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from netadmin.ca_runtime.app import create_runtime
from netadmin.ca_runtime.certificates import (
    create_certificate,
    load_key,
    new_key,
    options,
)
from netadmin.ca_runtime.store import AuthorityStore, durable
from tests.test_ca_runtime import TOKEN, body


def test_failed_atomic_publication_removes_staging_and_retains_original(tmp_path, monkeypatch):
    path = tmp_path / "ca.crt"
    path.write_bytes(b"previous public certificate")

    def fail(_source, _target):
        raise OSError("synthetic rename failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        durable(path, b"replacement")
    assert path.read_bytes() == b"previous public certificate"
    assert list(tmp_path.iterdir()) == [path]


def test_state_version_and_missing_wrapping_secret_never_regenerate_root(tmp_path):
    store = AuthorityStore(tmp_path)
    original = (tmp_path / "root.key").read_bytes()
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    (tmp_path / "manifest.json").write_text(json.dumps({**manifest, "version": 999}))
    with pytest.raises(ValueError, match="Unsupported"):
        AuthorityStore(tmp_path)
    assert (tmp_path / "root.key").read_bytes() == original
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "root.password").unlink()
    with pytest.raises(ValueError, match="recovery required"):
        AuthorityStore(tmp_path)
    assert (tmp_path / "root.key").read_bytes() == original
    assert store.status()["public_key_sha256"] == manifest["public_key_sha256"]


def test_root_recovery_passphrase_confirmation_and_algorithm_checks(tmp_path):
    store = AuthorityStore(tmp_path)
    store.create_root(body())
    with pytest.raises(ValueError, match="16 to 1024"):
        store.export_root({"password": "short"})
    with pytest.raises(ValueError, match="ARCHIVE ROOT"):
        store.archive_root({})
    assert (tmp_path / "root.key").exists()
    password = uuid.uuid4().hex.encode()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    with pytest.raises(ValueError, match="Unsupported CA key"):
        load_key(data, password)
    invalid_subject = body(organization="private\x00name")
    with pytest.raises(ValueError, match="Invalid organization"):
        options(invalid_subject)


def test_parent_must_be_currently_valid_before_signing_a_subordinate():
    key = new_key()
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Future Root")])
    parent = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=1))
        .not_valid_after(now + timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), True)
        .sign(key, hashes.SHA384())
    )
    child_options = options(body(days=30, path_length=0))
    child_key = new_key()
    with pytest.raises(ValueError, match="active CA"):
        create_certificate(child_options, child_key, parent, key)


def test_controller_rejects_malformed_requests_and_capacity_before_child_creation(tmp_path):
    app = create_runtime(tmp_path, TOKEN)
    client = app.test_client()
    headers = {"X-CA-Management-Token": TOKEN}
    assert client.get("/operations/" + uuid.uuid4().hex, headers=headers).status_code == 404
    assert client.post("/authorities/unknown", headers=headers, json={}).status_code == 404
    for path in (
        "/authorities/root",
        "/authorities/" + uuid.uuid4().hex + "/issue",
        "/authorities/" + uuid.uuid4().hex + "/revoke",
    ):
        assert client.post(path, headers=headers, json=[]).status_code == 400
    root_id = client.post("/authorities/root", headers=headers, json=body()).json["id"]
    store = app.extensions["ca_store"]
    for _ in range(16):
        directory = store.directory(uuid.uuid4().hex)
        directory.mkdir()
        (directory / "config.json").write_text("{}")
    response = client.post(
        "/authorities/subordinate",
        headers=headers,
        json=body(
            parent_id=root_id,
            days=30,
            path_length=0,
            service_host="ca.example.test",
            dns_suffixes="example.test",
        ),
    )
    assert response.status_code == 400
    assert "16" in response.json["error"]
    assert len(store.status()["authorities"]) == 1


def test_external_csr_signature_and_weak_key_are_rejected_without_new_authorities(tmp_path):
    app = create_runtime(tmp_path, TOKEN)
    client = app.test_client()
    headers = {"X-CA-Management-Token": TOKEN}
    root_id = client.post("/authorities/root", headers=headers, json=body()).json["id"]
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External")]))
        .sign(key, hashes.SHA256())
    )
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    invalid = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM).decode()
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - rejection fixture
    weak_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(csr.subject)
        .sign(weak, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    for pem in (invalid, weak_csr):
        response = client.post(
            "/authorities/subordinate",
            headers=headers,
            json=body(parent_id=root_id, days=30, path_length=0, csr=pem),
        )
        assert response.status_code == 400
    assert len(app.extensions["ca_store"].status()["authorities"]) == 1


def test_gateway_transport_errors_do_not_expose_diagnostics(tmp_path, monkeypatch):
    from netadmin.agents.ca import create_ca_agent

    token_path = tmp_path / "management-token"
    token_path.write_text(TOKEN)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", TOKEN)
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("CA_CONTROL_SOCKET", str(tmp_path / "ca.sock"))
    monkeypatch.setenv("CA_MANAGEMENT_TOKEN_FILE", str(token_path))

    def fail(_request):
        raise httpx.ReadTimeout("synthetic-secret-diagnostic")

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_kwargs: httpx.MockTransport(fail))
    app = create_ca_agent()
    client = app.test_client()
    response = client.get(
        "/authorities", headers={"Authorization": "Bearer " + TOKEN, "X-CA-Management-Token": TOKEN}
    )
    assert response.status_code == 502
    assert b"synthetic-secret-diagnostic" not in response.data
    assert b"inspect operation status" in response.data
    token_path.write_text("short")
    with pytest.raises(ValueError, match="too short"):
        create_ca_agent()


def test_archived_root_cannot_be_unlocked_with_another_private_key(tmp_path):
    store = AuthorityStore(tmp_path)
    root_id = store.create_root(body())["id"]
    password = TOKEN
    exported = store.export_root({"password": password})
    store.archive_root(
        {
            "confirmation": "ARCHIVE ROOT",
            "recovery_key": exported["key"],
            "recovery_password": password,
        }
    )
    from netadmin.ca_runtime.certificates import key_bytes, new_key

    wrong_key = key_bytes(new_key(), password.encode()).decode()
    with pytest.raises(ValueError, match="does not match"):
        store.key(root_id, {"recovery_key": wrong_key, "recovery_password": password})
    assert not (tmp_path / "root.key").exists()
    assert not (tmp_path / "root.password").exists()


def test_rejected_root_operation_replay_retains_original_certificate(tmp_path):
    app = create_runtime(tmp_path, TOKEN)
    client = app.test_client()
    headers = {"X-CA-Management-Token": TOKEN}
    root = client.post("/authorities/root", headers=headers, json=body()).json["id"]
    before = app.extensions["ca_store"].chain(root)
    payload = body()
    first = client.post("/authorities/root", headers=headers, json=payload)
    replay = client.post("/authorities/root", headers=headers, json=payload)
    assert first.status_code == replay.status_code == 400
    assert first.json == replay.json
    assert app.extensions["ca_store"].chain(root) == before
