"""CA interface forwarding, bounded uploads, downloads and uncertain outcomes."""

import io
import json
import uuid
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from tests.test_ca_runtime import TOKEN, body
from tests.test_ca_runtime_operations import configured  # noqa: F401
from tests.test_multi_service_ui import admin_client


@pytest.fixture
def web(configured, tmp_path, monkeypatch):  # noqa: F811 - imported shared pytest fixture
    state = configured
    app, client = admin_client(tmp_path / "web")
    settings = app.extensions["netadmin_settings"]
    app.extensions["netadmin_settings"] = replace(
        settings, ca_agent_url="https://ca.test:8084", ca_management_token=TOKEN
    )
    calls = []
    public = state.store.chain(state.authority_id).decode()

    def get(path):
        calls.append(("GET", path))
        if path == "authorities":
            return state.store.status()
        if path.endswith("/chain"):
            return {"pem": public}
        if path.endswith("/crl"):
            return {"pem": "synthetic-public-crl"}
        if path.endswith("/certificates"):
            return {"certificates": []}
        if path.startswith("operations/"):
            return {"state": "complete", "result": {"id": state.authority_id}}
        raise AssertionError("Unexpected controller path: " + path)

    def post(path, payload, **kwargs):
        calls.append(("POST", path, payload, kwargs))
        assert kwargs["timeout"] == 100
        return {"pem": public}

    remote = SimpleNamespace(get=get, post=post, read_only=lambda: False)
    monkeypatch.setattr("netadmin.ca_authorities_web.client", lambda: remote)
    return SimpleNamespace(
        app=app, client=client, remote=remote, calls=calls, state=state, public=public
    )


def test_authority_and_issuer_pages_and_public_downloads(web):
    root = "/certificates/authorities/" + web.state.authority_id
    assert b"Managed Issuer" in web.client.get("/certificates/authorities").data
    issued = web.client.get(root + "/issued")
    assert issued.status_code == 200
    assert b"Revoke a leaf certificate" in issued.data
    assert web.client.get(root + "/chain").data.decode() == web.public
    assert web.client.get(root + "/crl").data == b"synthetic-public-crl"
    operation_id = uuid.uuid4().hex
    result = web.client.get("/certificates/authorities/operations/" + operation_id)
    assert result.status_code == 200
    assert b"complete" in result.data
    assert ("GET", "operations/" + operation_id) in web.calls
    web.remote.read_only = lambda: True
    assert b"The agent is read-only" in web.client.get(root + "/issued").data
    web.remote.get = lambda _path: {"authorities": [], "certificates": []}
    assert web.client.get(root + "/issued").status_code == 404


def test_leaf_sign_and_revoke_use_selected_issuer_and_never_export_secrets(web):
    operation_id = uuid.uuid4().hex
    payload = {
        "request_id": operation_id,
        "issuer_id": web.state.authority_id,
        "csr": "synthetic-csr",
        "days": "7",
        "confirm": "yes",
    }
    result = web.client.post("/certificates/authorities/issue", data=payload)
    assert result.status_code == 200
    assert result.data.decode() == web.public
    assert result.headers["Cache-Control"] == "no-store"
    assert 'filename="certificate-chain.pem"' in result.headers["Content-Disposition"]
    assert web.calls[-1] == (
        "POST",
        "authorities/" + web.state.authority_id + "/issue",
        {"request_id": operation_id, "csr": "synthetic-csr", "days": "7"},
        {"timeout": 100},
    )
    result = web.client.post(
        "/certificates/authorities/revoke",
        data={
            "request_id": uuid.uuid4().hex,
            "issuer_id": web.state.authority_id,
            "serial": "beef",
            "reason": "1",
            "confirm": "yes",
        },
    )
    assert result.status_code == 302
    assert web.calls[-1][1] == "authorities/" + web.state.authority_id + "/revoke"
    assert web.calls[-1][2]["serial"] == "beef"
    assert web.calls[-1][2]["reason"] == "1"


def test_encrypted_recovery_upload_is_bounded_and_only_key_is_forwarded(web):
    recovery = {"key": "synthetic-encrypted-root-key", "ignored-secret": "never-forward"}
    result = web.client.post(
        "/certificates/authorities/archive-root",
        data={
            "request_id": uuid.uuid4().hex,
            "confirmation": "ARCHIVE ROOT",
            "confirm": "yes",
            "recovery_password": TOKEN,
            "recovery_file": (io.BytesIO(json.dumps(recovery).encode()), "root.json"),
        },
    )
    assert result.status_code == 302
    payload = web.calls[-1][2]
    assert payload["recovery_key"] == recovery["key"]
    assert payload["recovery_password"] == TOKEN
    assert "ignored-secret" not in payload
    for data in (
        b"not-json",
        b"[]",
        b"{}",
        json.dumps({"key": "x" * 16385}).encode(),
        b'{"key":' + b'"' + b"x" * 40000 + b'"}',
    ):
        assert (
            web.client.post(
                "/certificates/authorities/archive-root",
                data={
                    "request_id": uuid.uuid4().hex,
                    "confirm": "yes",
                    "recovery_file": (io.BytesIO(data), "root.json"),
                },
            ).status_code
            == 400
        )
    assert b"synthetic-encrypted-root-key" not in web.client.get("/audit").data
    assert TOKEN.encode() not in web.client.get("/audit").data


@pytest.mark.parametrize(
    "suffix", ["/invalid/chain", "/invalid/crl", "/invalid/issued", "/operations/invalid"]
)
def test_malformed_authority_and_operation_paths_are_rejected_without_forwarding(web, suffix):
    assert web.client.get("/certificates/authorities" + suffix).status_code == 404
    assert not web.calls


def test_mutations_validate_action_request_id_size_and_confirmation(web):
    for action, payload, status in (
        ("unknown", body(), 404),
        ("root", {}, 400),
        ("root", body(), 400),
        (
            "issue",
            {"request_id": uuid.uuid4().hex, "confirm": "yes", "issuer_id": "../escape"},
            400,
        ),
        ("root", {**body(), "common_name": "x" * 100001, "confirm": "yes"}, 413),
    ):
        assert (
            web.client.post("/certificates/authorities/" + action, data=payload).status_code
            == status
        )
    assert not web.calls


def test_lost_response_audits_unknown_and_preserves_operation_identity(web):
    operation_id = uuid.uuid4().hex

    def fail(*_args, **_kwargs):
        raise httpx.ReadTimeout("synthetic-private-error")

    web.remote.post = fail
    result = web.client.post(
        "/certificates/authorities/subordinate",
        data={**body(request_id=operation_id), "confirm": "yes"},
    )
    assert result.status_code == 409
    assert operation_id.encode() in result.data
    assert b"Check operation" in result.data
    assert b"synthetic-private-error" not in result.data
    audit = web.client.get("/audit").data
    assert operation_id.encode() in audit
    assert b"Unknown" in audit
    web.remote.get = fail
    for path in (
        "/certificates/authorities",
        "/certificates/authorities/" + web.state.authority_id + "/issued",
        "/certificates/authorities/operations/" + operation_id,
        "/certificates/authorities/" + web.state.authority_id + "/chain",
    ):
        result = web.client.get(path)
        assert result.status_code == 502
        assert b"synthetic-private-error" not in result.data


def test_known_rejection_shows_bounded_message_and_fails_audit(web):
    operation_id = uuid.uuid4().hex

    def reject(*_args, **_kwargs):
        response = httpx.Response(
            403,
            json={"error": "scope denied " * 100},
            request=httpx.Request("POST", "https://ca.test/authorities/root"),
        )
        raise httpx.HTTPStatusError("rejected", request=response.request, response=response)

    web.remote.post = reject
    response = web.client.post(
        "/certificates/authorities/root", data={**body(request_id=operation_id), "confirm": "yes"}
    )
    assert response.status_code == 400
    assert b"scope denied" in response.data
    assert b"scope denied " * 30 not in response.data
    assert operation_id.encode() in web.client.get("/audit").data


def test_download_requires_a_configured_management_connection(tmp_path):
    _app, client = admin_client(tmp_path)
    response = client.get("/certificates/authorities/" + uuid.uuid4().hex + "/chain")
    assert response.status_code == 409
    assert b"Configure the CA endpoint" in response.data


def test_issuer_inventory_forwards_validated_cursor_and_renders_next_page(web):
    original = web.remote.get
    cursor = uuid.uuid4().hex
    expected = "authorities/" + web.state.authority_id + "/certificates?after=" + cursor

    def get(path):
        if path == expected:
            web.calls.append(("GET", path))
            return {"certificates": [], "next_cursor": cursor}
        return original(path)

    web.remote.get = get
    path = "/certificates/authorities/" + web.state.authority_id + "/issued"
    response = web.client.get(path + "?after=" + cursor)
    assert response.status_code == 200
    assert ("GET", expected) in web.calls
    assert b"Next page" in response.data
    assert ("after=" + cursor).encode() in response.data
    assert web.client.get(path + "?after=invalid").status_code == 400
