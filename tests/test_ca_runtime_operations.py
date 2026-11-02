"""Native-issuer contracts, isolation, uncertain outcomes and process supervision."""

import json
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from netadmin.ca_runtime import issuer
from netadmin.ca_runtime.app import create_runtime
from tests.test_ca_runtime import TOKEN, body


@pytest.fixture
def configured(tmp_path, monkeypatch):
    app = create_runtime(tmp_path, TOKEN)
    client = app.test_client()
    headers = {"X-CA-Management-Token": TOKEN}
    root_id = client.post("/authorities/root", headers=headers, json=body()).json["id"]
    calls = []

    def jwk(arguments):
        calls.append(arguments)
        assert arguments[:3] == ["crypto", "jwk", "create"]
        public, encrypted = map(Path, arguments[3:5])
        assert public.parent == encrypted.parent
        assert arguments[5:] == [
            "--kty",
            "EC",
            "--crv",
            "P-256",
            "--password-file",
            str(public.parent / "provisioner.password"),
        ]
        assert len((public.parent / "provisioner.password").read_bytes()) >= 32
        public.write_text(json.dumps({"kty": "EC", "kid": "synthetic"}))
        encrypted.write_text("synthetic-encrypted-provisioner-jwe")
        return ""

    monkeypatch.setattr(issuer, "run", jwk)
    payload = body(
        parent_id=root_id,
        common_name="Managed Issuer",
        days=365,
        path_length=0,
        service_host="ca.example.test",
        dns_suffixes="example.test",
        ip_ranges="192.168.50.0/24",
        leaf_days=30,
    )
    result = client.post("/authorities/subordinate", headers=headers, json=payload)
    assert result.status_code == 200, result.json
    return SimpleNamespace(
        app=app,
        client=client,
        headers=headers,
        store=app.extensions["ca_store"],
        root_id=root_id,
        authority_id=result.json["id"],
        calls=calls,
        payload=payload,
    )


def test_managed_issuers_have_independent_keys_database_policy_and_credentials(configured):
    state = configured
    first = state.store.directory(state.authority_id)
    other = state.client.post(
        "/authorities/subordinate",
        headers=state.headers,
        json={**state.payload, "request_id": uuid.uuid4().hex, "common_name": "Second Issuer"},
    )
    assert other.status_code == 200
    second = state.store.directory(other.json["id"])
    configs = [json.loads((path / "config.json").read_text()) for path in (first, second)]
    assert [config["address"] for config in configs] == [":9100", ":9101"]
    assert configs[0]["db"]["dataSource"] != configs[1]["db"]["dataSource"]
    assert (first / "ca.key").read_bytes() != (second / "ca.key").read_bytes()
    assert (first / "provisioner.password").read_bytes() != (
        second / "provisioner.password"
    ).read_bytes()
    assert configs[0]["authority"]["policy"]["x509"] == {
        "allow": {"dns": ["example.test", "*.example.test"], "ip": ["192.168.50.0/24"]},
        "allowWildcardNames": False,
    }
    provisioner = configs[0]["authority"]["provisioners"][0]
    assert "policy" not in provisioner  # OSS ignores this location.
    assert provisioner["claims"]["maxTLSCertDuration"] == "720h"
    assert '"isCA": false' in provisioner["options"]["x509"]["template"]
    assert "https://ca.example.test:9100/1.0/crl" in provisioner["options"]["x509"]["template"]
    chain = x509.load_pem_x509_certificates((first / "issuing-chain.pem").read_bytes())
    assert len(chain) == 1
    assert chain[0] == state.store.certificate(state.authority_id)
    assert x509.load_pem_x509_certificate(
        (first / "root.crt").read_bytes()
    ) == state.store.certificate(state.root_id)


def leaf_csr():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.example.test")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("device.example.test")]), False)
        .sign(key, hashes.SHA256())
    )
    return csr


def test_leaf_signing_contract_replay_inventory_and_expiry(configured, monkeypatch):
    state = configured
    directory = state.store.directory(state.authority_id)
    csr = leaf_csr()
    calls = []

    def sign(arguments):
        calls.append(arguments)
        assert arguments[:2] == ["ca", "sign"]
        request, output = map(Path, arguments[2:4])
        assert request.parent == output.parent == directory
        assert request.read_bytes() == csr.public_bytes(Encoding.PEM)
        assert arguments[4:] == [
            "--not-after",
            "24h",
            "--ca-url",
            "https://localhost:9100",
            "--root",
            str(directory / "root.crt"),
            "--provisioner",
            "netadmin",
            "--provisioner-password-file",
            str(directory / "provisioner.password"),
        ]
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(state.store.certificate(state.authority_id).subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(csr.extensions[0].value, False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(state.store.key(state.authority_id, {}), hashes.SHA384())
        )
        output.write_bytes(
            certificate.public_bytes(Encoding.PEM) + state.store.chain(state.authority_id)
        )
        return ""

    monkeypatch.setattr(issuer, "run", sign)
    payload = {
        "request_id": uuid.uuid4().hex,
        "csr": csr.public_bytes(Encoding.PEM).decode(),
        "days": 1,
    }
    path = "/authorities/" + state.authority_id + "/issue"
    result = state.client.post(path, json=payload, headers=state.headers)
    assert result.status_code == 200
    assert state.client.post(path, json=payload, headers=state.headers).json == result.json
    assert len(calls) == 1
    inventory = state.client.get(
        "/authorities/" + state.authority_id + "/certificates", headers=state.headers
    )
    assert len(inventory.json["certificates"]) == 1
    assert inventory.json["certificates"][0]["pem"] == result.json["pem"]
    assert (
        state.client.get(
            "/authorities/" + state.authority_id + "/chain", headers=state.headers
        ).json["pem"]
        == state.store.chain(state.authority_id).decode()
    )
    long = state.client.post(
        path, json={**payload, "request_id": uuid.uuid4().hex, "days": 400}, headers=state.headers
    )
    assert long.status_code == 400
    assert "expiry" in long.json["error"]
    assert len(calls) == 1


def test_cli_failure_keeps_uncertain_operation_and_never_resigns(configured, monkeypatch):
    state = configured
    calls = []

    def fail(arguments):
        calls.append(arguments)
        raise subprocess.CalledProcessError(1, arguments, stderr="synthetic-private-diagnostic")

    monkeypatch.setattr(issuer, "run", fail)
    payload = {
        "request_id": uuid.uuid4().hex,
        "csr": leaf_csr().public_bytes(Encoding.PEM).decode(),
        "days": 1,
    }
    path = "/authorities/" + state.authority_id + "/issue"
    assert state.client.post(path, json=payload, headers=state.headers).status_code == 409
    status = state.client.get("/operations/" + payload["request_id"], headers=state.headers)
    assert status.json["state"] == "attempted"
    replay = state.client.post(path, json=payload, headers=state.headers)
    assert replay.status_code == 400
    assert "reconciliation" in replay.json["error"]
    assert len(calls) == 1
    assert b"synthetic-private-diagnostic" not in replay.data + status.data


def test_revocation_uses_decimal_serial_and_pinned_issuer_and_reconciles(configured, monkeypatch):
    state = configured
    directory = state.store.directory(state.authority_id)
    calls = []
    sequence = iter([False, True])
    monkeypatch.setattr(issuer, "revoked", lambda *_args: next(sequence))

    def run(arguments):
        calls.append(arguments)
        return "synthetic-ephemeral-revocation-token" if arguments[:2] == ["ca", "token"] else ""

    monkeypatch.setattr(issuer, "run", run)
    payload = {"request_id": uuid.uuid4().hex, "serial": "beef", "reason": "5"}
    path = "/authorities/" + state.authority_id + "/revoke"
    result = state.client.post(path, json=payload, headers=state.headers)
    assert result.json == {"revoked": True}
    flags = ["--ca-url", "https://localhost:9100", "--root", str(directory / "root.crt")]
    assert calls == [
        [
            "ca",
            "token",
            "48879",
            "--revoke",
            *flags,
            "--provisioner",
            "netadmin",
            "--provisioner-password-file",
            str(directory / "provisioner.password"),
        ],
        [
            "ca",
            "revoke",
            "48879",
            "--token",
            "synthetic-ephemeral-revocation-token",
            "--reasonCode",
            "5",
            *flags,
        ],
    ]
    monkeypatch.setattr(issuer, "revoked", lambda *_args: True)
    assert state.client.post(
        path, json={**payload, "request_id": uuid.uuid4().hex}, headers=state.headers
    ).json == {"revoked": True}
    assert len(calls) == 2
    monkeypatch.setattr(issuer, "revoked", lambda *_args: False)
    uncertain = state.client.post(
        path, json={**payload, "request_id": uuid.uuid4().hex}, headers=state.headers
    )
    assert uncertain.status_code == 409
    for invalid in ({"serial": "0"}, {"serial": "../escape"}, {"reason": "2"}):
        assert (
            state.client.post(
                path,
                json={**payload, **invalid, "request_id": uuid.uuid4().hex},
                headers=state.headers,
            ).status_code
            == 400
        )


def test_crl_transport_is_pinned_and_public_response_is_parsed(configured, monkeypatch):
    state = configured
    now = datetime.now(UTC)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(state.store.certificate(state.authority_id).subject)
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(123).revocation_date(now).build()
        )
        .sign(state.store.key(state.authority_id, {}), hashes.SHA384())
    )
    real_client = httpx.Client
    calls = []

    def transport(request):
        calls.append(request)
        assert str(request.url) == "https://localhost:9100/1.0/crl"
        return httpx.Response(200, content=crl.public_bytes(Encoding.DER))

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["verify"].verify_mode == 2
        assert kwargs["verify"].get_ca_certs(binary_form=True) == [
            state.store.certificate(state.root_id).public_bytes(Encoding.DER)
        ]
        return real_client(transport=httpx.MockTransport(transport))

    monkeypatch.setattr(httpx, "Client", client)
    assert issuer.revoked(state.store, state.authority_id, 123)
    assert not issuer.revoked(state.store, state.authority_id, 124)
    response = state.client.get(
        "/authorities/" + state.authority_id + "/crl", headers=state.headers
    )
    assert x509.load_pem_x509_crl(response.json["pem"].encode()) == crl
    assert len(calls) == 3


def test_cli_adapter_bounds_execution_and_strips_output(monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="  ok\n")

    monkeypatch.setattr(subprocess, "run", execute)
    assert issuer.run(["ca", "health"]) == "ok"
    assert calls[0][0] == ["/usr/local/bin/step", "ca", "health"]
    assert calls[0][1] == {
        "capture_output": True,
        "check": True,
        "text": True,
        "timeout": 30,
        "stdin": subprocess.DEVNULL,
    }


def test_supervisor_reuses_restarts_expires_and_reaps_issuer_processes(configured, monkeypatch):
    state = configured
    created = []

    class Process:
        def __init__(self):
            self.code = None
            self.terminated = 0
            self.killed = 0
            self.waits = 0

        def poll(self):
            return self.code

        def terminate(self):
            self.terminated += 1

        def kill(self):
            self.killed += 1
            self.code = -9

        def wait(self, timeout):
            assert timeout == 5
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("step-ca", timeout)
            return self.code

    def start(command, **kwargs):
        assert command == [
            "/usr/local/bin/step-ca",
            str(state.store.directory(state.authority_id) / "config.json"),
            "--password-file",
            str(state.store.directory(state.authority_id) / "password"),
        ]
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] is kwargs["stderr"]
        process = Process()
        created.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", start)
    supervisor = issuer.Issuers(state.store)
    supervisor.reconcile()
    supervisor.reconcile()
    assert len(created) == 1
    created[0].code = 1
    supervisor.reconcile()
    assert len(created) == 2
    original = state.store.certificate
    monkeypatch.setattr(
        state.store,
        "certificate",
        lambda authority_id: SimpleNamespace(
            not_valid_after_utc=datetime.now(UTC) - timedelta(seconds=1)
        ),
    )
    supervisor.reconcile()
    assert created[1].terminated == 1
    monkeypatch.setattr(state.store, "certificate", original)
    supervisor.close()
    assert created[1].killed == 1
    assert created[1].waits == 2


def test_external_subordinate_cannot_omit_a_managed_parents_policy(configured):
    state = configured
    issuer.check_parent_policy(
        state.store,
        state.authority_id,
        issuer.policy({"dns_suffixes": "example.test", "leaf_days": 10}),
    )
    before = len(state.store.status()["authorities"])
    response = state.client.post(
        "/authorities/subordinate",
        headers=state.headers,
        json=body(
            parent_id=state.authority_id,
            common_name="External",
            days=30,
            path_length=0,
            csr=leaf_csr().public_bytes(Encoding.PEM).decode(),
        ),
    )
    assert response.status_code == 400
    assert "explicit inherited issuance scope" in response.json["error"]
    assert len(state.store.status()["authorities"]) == before
