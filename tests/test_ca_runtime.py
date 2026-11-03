"""Authority identity, hierarchy, recovery, retries and management boundaries."""

import json
import uuid
from dataclasses import replace
from ipaddress import ip_network

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from netadmin.ca_runtime.app import create_runtime
from netadmin.ca_runtime.certificates import PEM, options
from netadmin.ca_runtime.store import AuthorityStore
from tests.test_multi_service_ui import admin_client

TOKEN = uuid.uuid4().hex + uuid.uuid4().hex


def body(**values):
    return {
        "request_id": uuid.uuid4().hex,
        "common_name": "Network Root",
        "days": 7300,
        "path_length": 2,
        **values,
    }


@pytest.fixture
def runtime(tmp_path):
    app = create_runtime(tmp_path, TOKEN)
    return app, app.test_client(), {"X-CA-Management-Token": TOKEN}


def test_first_boot_persists_key_and_root_identity(runtime, tmp_path):
    app, client, headers = runtime
    store = app.extensions["ca_store"]
    before = (tmp_path / "root.key").read_bytes()
    assert store.status()["state"] == "key_ready"
    assert (
        AuthorityStore(tmp_path).status()["public_key_sha256"]
        == store.status()["public_key_sha256"]
    )
    payload = body(organization="Network", country="gb", sans="ca.example.test,192.168.1.1")
    response = client.post("/authorities/root", json=payload, headers=headers)
    assert response.status_code == 200
    authority_id = response.json["id"]
    cert = store.certificate(authority_id)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Network Root"
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "GB"
    assert cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["ca.example.test"]
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 7300
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 2
    assert client.post("/authorities/root", json=payload, headers=headers).json == response.json
    assert (tmp_path / "root.key").read_bytes() == before
    assert client.post("/authorities/root", json=body(), headers=headers).status_code == 400
    assert b"PRIVATE KEY" not in client.get("/authorities", headers=headers).data


def test_external_subordinate_subject_public_key_parent_limits_and_recovery(runtime):
    app, client, headers = runtime
    store = app.extensions["ca_store"]
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted CSR name")]))
        .sign(key, hashes.SHA256())
    )
    payload = body(
        parent_id=root_id,
        common_name="Device Issuing CA",
        days=365,
        path_length=0,
        csr=csr.public_bytes(PEM).decode(),
    )
    result = client.post("/authorities/subordinate", json=payload, headers=headers)
    assert result.status_code == 200
    cert = store.certificate(result.json["id"])
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.issuer == store.certificate(root_id).subject
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Device Issuing CA"
    assert len(x509.load_pem_x509_certificates(store.chain(result.json["id"]))) == 2
    for invalid in ({"days": 8000}, {"path_length": 2}):
        assert (
            client.post(
                "/authorities/subordinate",
                json={**payload, **invalid, "request_id": uuid.uuid4().hex},
                headers=headers,
            ).status_code
            == 400
        )
    exported = client.post(
        "/authorities/export-root",
        json={"password": "a separate recovery passphrase"},
        headers=headers,
    )
    assert exported.status_code == 200
    assert "PRIVATE KEY" in exported.json["key"]
    assert "password" not in exported.json
    archived = body(
        recovery_key=exported.json["key"],
        recovery_password="a separate recovery passphrase",  # noqa: S106
        confirmation="ARCHIVE ROOT",
    )
    assert (
        client.post("/authorities/archive-root", json=archived, headers=headers).status_code == 200
    )
    assert AuthorityStore(store.root).status()["root_online"] is False
    assert (
        client.post(
            "/authorities/subordinate",
            json={
                **payload,
                "request_id": uuid.uuid4().hex,
                "recovery_key": exported.json["key"],
                "recovery_password": "a separate recovery passphrase",
            },
            headers=headers,
        ).status_code
        == 200
    )
    assert not (store.root / "root.key").exists()
    assert not (store.root / "root.password").exists()


def test_management_auth_missing_state_and_changed_retry(runtime, tmp_path):
    _, client, headers = runtime
    assert client.get("/authorities").status_code == 403
    payload = body()
    assert client.post("/authorities/root", json=payload).status_code == 403
    assert client.post("/authorities/root", json=payload, headers=headers).status_code == 200
    assert (
        client.post(
            "/authorities/root", json={**payload, "common_name": "Changed"}, headers=headers
        ).status_code
        == 400
    )
    status = client.get("/operations/" + payload["request_id"], headers=headers)
    assert status.json["state"] == "complete"
    (tmp_path / "root.key").unlink()
    assert client.post("/authorities/root", json=body(), headers=headers).status_code == 400
    other = tmp_path / "incomplete"
    other.mkdir()
    (other / "root.key").write_text("partial state")
    with pytest.raises(ValueError, match="recovery required"):
        AuthorityStore(other)


@pytest.mark.parametrize(
    "values",
    [
        {"days": True},
        {"days": 0},
        {"days": 36501},
        {"path_length": -1},
        {"country": "GBR"},
        {"common_name": "\n"},
        {"sans": "bad/name"},
    ],
)
def test_authority_options_reject_invalid_inputs(values):
    payload = {**body(), **values}
    with pytest.raises(ValueError):
        options(payload)


def test_authority_ui_empty_state_and_sensitive_exports(tmp_path, monkeypatch):
    app, client = admin_client(tmp_path)
    assert client.get("/certificates").status_code == 302
    assert b"Connect CA containers" in client.get("/certificates/authorities").data
    settings = app.extensions["netadmin_settings"]
    app.extensions["netadmin_settings"] = replace(
        settings, ca_agent_url="https://ca.test:8084", ca_management_token=TOKEN
    )
    runtime = create_runtime(tmp_path / "runtime", TOKEN).test_client()
    from netadmin.services.agents import AgentClient

    def get(self, path, **_kwargs):
        if path == "capabilities":
            return {"read_only": False}
        assert self.headers["X-CA-Management-Token"] == TOKEN
        result = runtime.get("/" + path, headers={"X-CA-Management-Token": TOKEN})
        return result.json

    def post(self, path, payload, **_kwargs):
        result = runtime.post("/" + path, json=payload, headers={"X-CA-Management-Token": TOKEN})
        assert result.status_code == 200
        return result.json

    monkeypatch.setattr(AgentClient, "get", get)
    monkeypatch.setattr(AgentClient, "post", post)
    page = client.get("/certificates/authorities")
    assert page.status_code == 200
    assert b"Create root certificate" in page.data
    payload = {**body(), "confirm": "yes"}
    assert client.post("/certificates/authorities/root", data=payload).status_code == 302
    exported = client.post(
        "/certificates/authorities/export-root",
        data={
            "request_id": uuid.uuid4().hex,
            "confirm": "yes",
            "password": "a separate recovery passphrase",
        },
    )
    assert exported.status_code == 200
    assert exported.headers["Cache-Control"] == "no-store"
    assert "ENCRYPTED PRIVATE KEY" in json.loads(exported.data)["key"]
    assert b"a separate recovery passphrase" not in client.get("/audit").data


def test_lifecycle_agent_requires_both_scopes_and_honors_read_only(tmp_path, monkeypatch):
    import httpx

    from netadmin.agents.ca import create_ca_agent

    token_path = tmp_path / "management-token"
    token_path.write_text(TOKEN)
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic-leaf-token")
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("CA_CONTROL_SOCKET", str(tmp_path / "ca.sock"))
    monkeypatch.setenv("CA_MANAGEMENT_TOKEN_FILE", str(token_path))
    seen = []

    def respond(request):
        seen.append(request)
        assert request.headers["X-CA-Management-Token"] == TOKEN
        return httpx.Response(200, json={"state": "key_ready"})

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_kwargs: httpx.MockTransport(respond))
    client = create_ca_agent().test_client()
    headers = {"Authorization": "Bearer synthetic-leaf-token"}
    assert client.get("/authorities").status_code == 401
    assert client.post("/authorities/root", headers=headers, json=body()).status_code == 403
    headers["X-CA-Management-Token"] = TOKEN
    assert client.get("/authorities", headers=headers).json == {"state": "key_ready"}
    assert seen[-1].url.path == "/authorities"
    assert client.post("/authorities/root", headers=headers, json=body()).status_code == 200
    assert seen[-1].url.path == "/authorities/root"
    count = len(seen)
    monkeypatch.setenv("NETADMIN_AGENT_READ_ONLY", "true")
    assert client.post("/authorities/root", headers=headers, json=body()).status_code == 403
    assert len(seen) == count


def test_legacy_state_is_not_reinitialized_and_archival_requires_matching_key(tmp_path):
    legacy = tmp_path / "legacy"
    (legacy / "config").mkdir(parents=True)
    (legacy / "config/ca.json").write_text("{}")
    with pytest.raises(ValueError, match="explicit migration"):
        AuthorityStore(legacy)
    assert not (legacy / "root.key").exists()
    store = AuthorityStore(tmp_path / "new")
    store.create_root(body())
    from netadmin.ca_runtime.certificates import key_bytes, new_key

    wrong = key_bytes(new_key(), b"synthetic-separate-passphrase").decode()
    with pytest.raises(ValueError, match="does not match"):
        store.archive_root(
            {
                "confirmation": "ARCHIVE ROOT",
                "recovery_key": wrong,
                "recovery_password": "synthetic-separate-passphrase",
            }
        )
    assert (store.root / "root.key").exists()
    assert (store.root / "root.password").exists()


def test_external_subordinate_scope_becomes_certificate_constraints(runtime):
    app, client, headers = runtime
    root_id = client.post("/authorities/root", json=body(), headers=headers).json["id"]
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External CA")]))
        .sign(key, hashes.SHA256())
    )
    result = client.post(
        "/authorities/subordinate",
        headers=headers,
        json=body(
            parent_id=root_id,
            common_name="External CA",
            days=365,
            path_length=0,
            dns_suffixes="devices.example.test",
            ip_ranges="192.168.50.0/24",
            csr=csr.public_bytes(PEM).decode(),
        ),
    )
    assert result.status_code == 200
    certificate = app.extensions["ca_store"].certificate(result.json["id"])
    extension = certificate.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical
    assert x509.DNSName("devices.example.test") in extension.value.permitted_subtrees
    assert x509.IPAddress(ip_network("192.168.50.0/24")) in extension.value.permitted_subtrees


def test_parent_policy_cannot_be_expanded(tmp_path):
    from netadmin.ca_runtime.issuer import check_parent_policy, policy, service_host

    store = AuthorityStore(tmp_path)
    root_id = store.create_root(body())["id"]
    metadata = store.metadata(root_id)
    metadata["policy"] = policy(
        {"dns_suffixes": "example.test", "ip_ranges": "192.168.50.0/24", "leaf_days": 30}
    )
    (store.directory(root_id) / "metadata.json").write_text(json.dumps(metadata))
    check_parent_policy(store, root_id, policy({"dns_suffixes": "example.test", "leaf_days": 10}))
    for child in (
        {"dns_suffixes": "outside.test"},
        {"ip_ranges": "10.0.0.0/8"},
        {"dns_suffixes": "example.test", "leaf_days": 365},
    ):
        child_policy = policy(child)
        with pytest.raises(ValueError, match="exceeds parent"):
            check_parent_policy(store, root_id, child_policy)
    for invalid in ("one.example.test,two.example.test", "*.example.test", "https://ca.test"):
        with pytest.raises(ValueError):
            service_host({"service_host": invalid})


def test_authority_routes_require_admin_and_csrf(tmp_path):
    app, client = admin_client(tmp_path)
    standard = app.extensions["netadmin_store"].create_session("ordinary", "standard", 60)
    client.set_cookie("netadmin_session", standard)
    assert client.get("/certificates/authorities").status_code == 403
    assert client.post("/certificates/authorities/root", data=body()).status_code == 403
    admin = app.extensions["netadmin_store"].create_session("root", "admin", 60)
    client.set_cookie("netadmin_session", admin)
    app.config["WTF_CSRF_ENABLED"] = True
    assert (
        client.post("/certificates/authorities/root", data={**body(), "confirm": "yes"}).status_code
        == 400
    )
