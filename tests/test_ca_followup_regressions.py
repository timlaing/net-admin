"""Deterministic CA guards, shutdown escalation and indexed inventory migration."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from netadmin.ca_runtime import isolation, issuer
from netadmin.ca_runtime.certificates import CAInputError, new_key
from netadmin.ca_runtime.inventory import CertificateInventory
from netadmin.ca_runtime.store import AuthorityStore
from tests.test_ca_runtime import body
from tests.test_ca_runtime_operations import configured, leaf_csr  # noqa: F401


def test_nonisolated_issuer_gets_database_parent_directory(configured, monkeypatch):  # noqa: F811
    monkeypatch.delenv("CA_ISOLATE_ISSUERS", raising=False)
    directory = configured.store.directory(configured.authority_id) / "runtime"
    assert not directory.exists()
    assert isolation.prepare(configured.store, configured.authority_id) == {}
    assert directory.is_dir()
    assert directory.stat().st_mode & 0o777 == 0o700


def test_ineligible_stubborn_child_is_killed_after_grace_period(configured, monkeypatch):  # noqa: F811
    state = configured
    supervisor = issuer.Issuers(state.store)
    clock = [0.0]
    code = [None]
    events = []
    monkeypatch.setattr(issuer.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        state.store,
        "certificate",
        lambda _id: SimpleNamespace(not_valid_after_utc=datetime.now(UTC) - timedelta(days=1)),
    )
    supervisor.processes[state.authority_id] = SimpleNamespace(
        poll=lambda: code[0],
        terminate=lambda: events.append("terminate"),
        kill=lambda: events.append("kill"),
    )
    supervisor.reconcile()
    clock[0] = 4.9
    supervisor.reconcile()
    assert events == ["terminate"]
    clock[0] = 5.0
    supervisor.reconcile()
    assert events == ["terminate", "kill"]
    code[0] = -9
    supervisor.reconcile()
    assert state.authority_id not in supervisor.stopping_at


def test_root_certificate_replacement_is_rejected_without_rekeying(configured, tmp_path):  # noqa: F811
    state = configured
    other = AuthorityStore(tmp_path / "other-root")
    other_id = other.create_root(body())["id"]
    root_key = (state.store.root / "root.key").read_bytes()
    replacement = other.certificate(other_id).public_bytes(Encoding.PEM)
    path = state.store.directory(state.root_id) / "ca.crt"
    path.write_bytes(replacement)
    with pytest.raises(CAInputError, match="Root certificate does not match"):
        AuthorityStore(state.store.root)
    assert (state.store.root / "root.key").read_bytes() == root_key
    assert path.read_bytes() == replacement


def test_nonmanaged_leaf_requests_and_missing_wrap_secret_replay_rejections(
    configured,  # noqa: F811
    monkeypatch,
):
    state = configured
    csr = leaf_csr().public_bytes(Encoding.PEM).decode()
    external = state.store.create_subordinate(
        body(parent_id=state.root_id, common_name="External", csr=csr, days=30, path_length=0)
    )["id"]
    monkeypatch.setattr(
        issuer, "run", lambda *_args: pytest.fail("Rejected input must not run the native CLI")
    )
    for authority_id in (state.root_id, external):
        payload = {"request_id": uuid.uuid4().hex, "csr": csr, "days": 1}
        path = "/authorities/" + authority_id + "/issue"
        response = state.client.post(path, json=payload, headers=state.headers)
        assert response.status_code == 400
        assert "managed issuing authority" in response.json["error"]
        assert state.client.post(path, json=payload, headers=state.headers).json == response.json
        record = json.loads(
            (state.store.root / "operations" / (payload["request_id"] + ".json")).read_text()
        )
        assert record["state"] == "rejected"
    (state.store.directory(state.authority_id) / "password").unlink()
    payload = body(
        parent_id=state.authority_id,
        common_name="Child",
        days=1,
        path_length=0,
        dns_suffixes="example.test",
        ip_ranges="192.168.50.0/24",
        leaf_days=1,
        csr=csr,
    )
    response = state.client.post("/authorities/subordinate", json=payload, headers=state.headers)
    assert response.status_code == 400
    assert "signing material" in response.json["error"]
    assert (
        state.client.post("/authorities/subordinate", json=payload, headers=state.headers).json
        == response.json
    )


def public_leaf(state, *, wrong_key=False):
    parent = state.store.certificate(state.authority_id)
    csr = leaf_csr()
    now = datetime.now(UTC)
    key = new_key() if wrong_key else state.store.key(state.authority_id, {})
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(parent.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(False, None), True)
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.PEM)
        .decode()
    )


def test_legacy_inventory_import_happens_once_and_skips_invalid_outputs(configured, monkeypatch):  # noqa: F811
    state = configured
    directory = state.store.directory(state.authority_id)
    pem = public_leaf(state)
    operation_id = uuid.uuid4().hex
    (directory / (operation_id + ".pem")).write_text(pem)
    (directory / (uuid.uuid4().hex + ".pem")).write_text("invalid public output")
    (directory / (uuid.uuid4().hex + ".pem")).write_text(public_leaf(state, wrong_key=True))
    (directory / (uuid.uuid4().hex + ".pem")).write_bytes(
        state.store.certificate(state.authority_id).public_bytes(Encoding.PEM)
    )
    inventory = state.store.inventory
    assert inventory.page(directory, "") == ([pem], None)
    assert inventory.path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(
        Path, "glob", lambda *_a, **_k: pytest.fail("Indexed pages must not rescan PEM files")
    )
    for number in range(60):
        inventory.record(directory, f"{number:032x}", pem)
    first, cursor = inventory.page(directory, "")
    assert len(first) == 50
    assert cursor == f"{49:032x}"
    second, cursor = inventory.page(directory, cursor)
    assert len(second) == 11
    assert cursor is None
    assert CertificateInventory(state.store.root).page(directory, "") == (first, f"{49:032x}")


def test_public_inventory_database_errors_are_bounded(configured):  # noqa: F811
    state = configured
    state.store.inventory.path.write_bytes(b"synthetic-private-diagnostic")
    directory = state.store.directory(state.authority_id)
    with pytest.raises(OSError, match=r"^Public certificate inventory unavailable$"):
        state.store.inventory.page(directory, "")


def test_repaired_certificate_cannot_cancel_pending_child_shutdown(configured, monkeypatch):  # noqa: F811
    state = configured
    original = state.store.certificate
    supervisor = issuer.Issuers(state.store)
    code = [None]
    clock = [0]
    events = []
    monkeypatch.setattr(issuer.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        state.store,
        "certificate",
        lambda _id: SimpleNamespace(not_valid_after_utc=datetime.now(UTC) - timedelta(days=1)),
    )
    supervisor.processes[state.authority_id] = SimpleNamespace(
        poll=lambda: code[0],
        terminate=lambda: events.append("terminate"),
        kill=lambda: events.append("kill"),
    )
    monkeypatch.setattr(supervisor, "_start", lambda _path: events.append("restart"))
    supervisor.reconcile()
    monkeypatch.setattr(state.store, "certificate", original)
    clock[0] = 4
    supervisor.reconcile()
    assert events == ["terminate"]
    clock[0] = 5
    supervisor.reconcile()
    assert events == ["terminate", "kill"]
    code[0] = -9
    supervisor.reconcile()
    assert events == ["terminate", "kill", "restart"]


def test_supervisor_start_failures_are_bounded_and_output_is_drained(
    configured,  # noqa: F811
    monkeypatch,
    caplog,
):
    import io

    state = configured
    supervisor = issuer.Issuers(state.store)
    real_start = supervisor._start
    monkeypatch.setattr(
        supervisor,
        "_start",
        lambda _path: (_ for _ in ()).throw(OSError("synthetic-private-diagnostic")),
    )
    supervisor.reconcile()
    assert "Issuer unavailable" in caplog.text
    assert "synthetic-private-diagnostic" not in caplog.text
    process = SimpleNamespace(stdout=io.BytesIO(b"synthetic native log\n"))
    monkeypatch.setattr(issuer.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        issuer.threading,
        "Thread",
        lambda **kwargs: SimpleNamespace(start=lambda: kwargs["target"](*kwargs["args"])),
    )
    real_start(state.store.directory(state.authority_id) / "config.json")
    assert supervisor.processes[state.authority_id] is process
    assert (
        state.store.directory(state.authority_id) / "service.log"
    ).read_bytes() == b"synthetic native log\n"


def test_interrupted_inventory_transaction_rolls_back(configured):  # noqa: F811
    state = configured
    operation_id = uuid.uuid4().hex

    def interrupted():
        with state.store.inventory.connection() as connection:
            connection.execute(
                "INSERT INTO certificates VALUES (?, ?, ?)",
                (state.authority_id, operation_id, "not committed"),
            )
            raise RuntimeError("synthetic transaction failure")

    with pytest.raises(RuntimeError, match="transaction failure"):
        interrupted()
    assert state.store.inventory.page(state.store.directory(state.authority_id), "") == ([], None)
