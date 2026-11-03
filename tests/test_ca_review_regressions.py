"""Review regressions: ownership boundaries, transactional setup and supervision."""

import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from netadmin.ca_runtime import isolation, issuer
from netadmin.ca_runtime.certificates import CAInputError, key_bytes, new_key, options
from netadmin.ca_runtime.store import AuthorityStore
from tests.test_ca_runtime import body
from tests.test_ca_runtime_operations import configured, leaf_csr  # noqa: F401


@pytest.mark.parametrize("value", [None, False, 0, [], {}])
def test_falsy_nonstring_sans_are_rejected(value):
    payload = body(sans=value)
    with pytest.raises(ValueError, match="SANs"):
        options(payload)


def test_existing_manifest_rejects_replaced_key_pair(tmp_path):
    store = AuthorityStore(tmp_path)
    password = b"independent-synthetic-password"
    (tmp_path / "root.password").write_bytes(password)
    replacement = key_bytes(new_key(), password)
    (tmp_path / "root.key").write_bytes(replacement)
    with pytest.raises(CAInputError, match="fingerprint"):
        AuthorityStore(tmp_path)
    assert (tmp_path / "manifest.json").read_text() == json.dumps(store.manifest)
    assert (tmp_path / "root.key").read_bytes() == replacement


def test_issuer_setup_failure_rolls_back_and_records_stable_rejection(configured, monkeypatch):  # noqa: F811
    state = configured
    before = set((state.store.root / "authorities").iterdir())
    payload = body(
        parent_id=state.root_id,
        common_name="Failed issuer",
        days=30,
        path_length=0,
        dns_suffixes="example.test",
        service_host="localhost",
        leaf_days=1,
    )

    def fail(*_args):
        raise OSError("synthetic-private-diagnostic")

    monkeypatch.setattr(issuer, "configure", fail)
    response = state.client.post("/authorities/subordinate", json=payload, headers=state.headers)
    assert response.status_code == 400
    assert "rolled back" in response.json["error"]
    assert set((state.store.root / "authorities").iterdir()) == before
    replay = state.client.post("/authorities/subordinate", json=payload, headers=state.headers)
    assert replay.json == response.json
    record = json.loads(
        (state.store.root / "operations" / (payload["request_id"] + ".json")).read_text()
    )
    assert record["state"] == "rejected"
    assert "synthetic-private-diagnostic" not in json.dumps(record)


def test_external_parent_and_overpolicy_lifetime_are_deterministic_rejections(configured):  # noqa: F811
    state = configured
    external = state.store.create_subordinate(
        body(
            parent_id=state.root_id,
            common_name="Externally held",
            days=30,
            path_length=1,
            csr=leaf_csr().public_bytes(Encoding.PEM).decode(),
        )
    )["id"]
    payload = body(parent_id=external, common_name="Child", days=1, path_length=0)
    # External CSR mode avoids managed-policy validation and reaches the key guard.
    payload["csr"] = leaf_csr().public_bytes(Encoding.PEM).decode()
    payload["request_id"] = uuid.uuid4().hex
    response = state.client.post("/authorities/subordinate", json=payload, headers=state.headers)
    assert response.status_code == 400
    assert "externally held" in response.json["error"]
    issue = {"csr": payload["csr"], "days": 31, "request_id": uuid.uuid4().hex}
    path = "/authorities/" + state.authority_id + "/issue"
    response = state.client.post(path, json=issue, headers=state.headers)
    assert response.status_code == 400
    assert "issuer policy" in response.json["error"]
    assert not (state.store.directory(state.authority_id) / (issue["request_id"] + ".csr")).exists()
    assert state.client.post(path, json=issue, headers=state.headers).json == response.json


def test_inventory_pages_have_stable_nonoverlapping_cursor(configured):  # noqa: F811
    state = configured
    directory = state.store.directory(state.authority_id)
    pem = state.store.certificate(state.authority_id).public_bytes(Encoding.PEM)
    for number in range(51):
        state.store.inventory.record(directory, f"{number:032x}", pem.decode())
    path = "/authorities/" + state.authority_id + "/certificates"
    page = state.client.get(path, headers=state.headers).json
    assert len(page["certificates"]) == 50
    assert page["next_cursor"] == f"{49:032x}"
    page = state.client.get(path + "?after=" + page["next_cursor"], headers=state.headers).json
    assert len(page["certificates"]) == 1
    assert page["next_cursor"] is None
    assert state.client.get(path + "?after=../invalid", headers=state.headers).status_code == 400


def test_corrupt_issuer_does_not_stop_healthy_siblings(configured, monkeypatch):  # noqa: F811
    state = configured
    directory = state.store.root / "authorities" / uuid.uuid4().hex
    directory.mkdir()
    (directory / "config.json").write_text("{}")
    (directory / "ca.crt").write_text("malformed certificate")
    starts = []
    monkeypatch.setattr(
        issuer.Issuers, "_start", lambda _self, path: starts.append(path.parent.name)
    )
    supervisor = issuer.Issuers(state.store)
    process = SimpleNamespace(poll=lambda: None, terminate=lambda: starts.append("stopped corrupt"))
    supervisor.processes[directory.name] = process
    supervisor.reconcile()
    assert state.authority_id in starts
    assert "stopped corrupt" in starts
    assert directory.name not in starts


def test_native_logs_rotate_and_remain_bounded(tmp_path):
    path = tmp_path / "service.log"
    issuer.capture_log(io.BytesIO(b"x" * (3 * 1024 * 1024 + 17)), path)
    assert path.stat().st_size <= 1024 * 1024
    assert path.with_suffix(".log.1").stat().st_size <= 1024 * 1024
    assert len(list(tmp_path.iterdir())) == 2
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.with_suffix(".log.1").stat().st_mode & 0o777 == 0o600


def test_isolation_passes_unique_identity_and_only_explicit_inputs(configured, monkeypatch):  # noqa: F811
    state = configured
    monkeypatch.setenv("CA_ISOLATE_ISSUERS", "1")
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    owners = []
    monkeypatch.setattr(
        isolation.os, "chown", lambda path, uid, gid: owners.append((Path(path).name, uid, gid))
    )
    identity = isolation.prepare(state.store, state.authority_id)
    assert identity == {"user": 20000, "group": 20000, "extra_groups": (), "umask": 0o077}
    assert {name for name, _uid, _gid in owners} == {
        "runtime",
        "config.json",
        "root.crt",
        "issuing-chain.pem",
        "ca.key",
        "password",
    }
    assert (state.store.root / "root.key").stat().st_mode & 0o777 == 0o600
    assert (
        state.store.directory(state.authority_id) / "metadata.json"
    ).stat().st_mode & 0o777 == 0o600
    with pytest.raises(CAInputError, match="unexpected ownership"):
        isolation.prepare(state.store, state.authority_id)
    metadata_path = state.store.directory(state.authority_id) / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata_path.write_text(json.dumps({**metadata, "port": 9000}))
    with pytest.raises(CAInputError, match="port identity"):
        isolation.prepare(state.store, state.authority_id)
    env = isolation.environment(state.store.directory(state.authority_id))
    assert set(env) == {"PATH", "HOME"}
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 1000)
    with pytest.raises(CAInputError, match="privileged"):
        isolation.prepare(state.store, state.authority_id)
