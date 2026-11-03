"""Review and release regressions for bounded migration and recoverable issuance."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from netadmin.ca_runtime import issuer
from tests.test_ca_followup_regressions import public_leaf
from tests.test_ca_runtime import body
from tests.test_ca_runtime_operations import configured, leaf_csr  # noqa: F401
from tests.test_dns_agent import AUTH, agent


@pytest.fixture
def state(configured):  # noqa: F811
    return configured


def test_malformed_owner_is_input_error_not_bind_failure(tmp_path, monkeypatch):
    client, _main = agent(tmp_path, monkeypatch)
    response = client.get(
        "/records/addresses?zone=existing.example&name=bad..existing.example.", headers=AUTH
    )
    assert response.status_code == 400
    assert response.json == {"error": "Invalid record name or zone"}


def test_unknown_parent_replays_a_deterministic_rejection(state):
    payload = body(
        parent_id=uuid.uuid4().hex,
        common_name="Child",
        dns_suffixes="example.test",
        service_host="localhost",
    )
    before = len(state.store.status()["authorities"])
    response = state.client.post("/authorities/subordinate", json=payload, headers=state.headers)
    assert response.status_code == 400
    assert response.json["error"] == "Unknown parent authority"
    assert (
        state.client.post("/authorities/subordinate", json=payload, headers=state.headers).json
        == response.json
    )
    record = json.loads(
        (state.store.root / "operations" / (payload["request_id"] + ".json")).read_text()
    )
    assert record["state"] == "rejected"
    assert len(state.store.status()["authorities"]) == before


def test_unreadable_legacy_leaf_is_retried_before_import_completes(state, monkeypatch):
    directory = state.store.directory(state.authority_id)
    path = directory / (uuid.uuid4().hex + ".pem")
    pem = public_leaf(state)
    path.write_text(pem)
    original = Path.read_text

    def read(candidate, *args, **kwargs):
        if candidate == path:
            raise OSError("synthetic temporary read failure")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    assert state.store.inventory.page(directory, "") == ([], None)
    assert state.store.inventory.pending(directory)
    monkeypatch.setattr(Path, "read_text", original)
    assert state.store.inventory.page(directory, "") == ([pem], None)
    assert not state.store.inventory.pending(directory)


def test_first_import_is_batched_and_restart_does_not_lose_progress(state, monkeypatch):
    directory = state.store.directory(state.authority_id)
    pem = public_leaf(state)
    for number in range(61):
        (directory / (f"{number:032x}" + ".pem")).write_text(pem)
    # Malformed bytes are invalid output, not a temporary filesystem failure.
    (directory / (uuid.uuid4().hex + ".pem")).write_bytes(b"\xff")
    monkeypatch.setattr("netadmin.ca_runtime.inventory.time.monotonic", lambda: 0)
    first, _cursor = state.store.inventory.page(directory, "")
    assert len(first) <= 50
    assert state.store.inventory.pending(directory)
    state.store.inventory.close()
    for _ in range(3):
        state.store.inventory.page(directory, "")
        if not state.store.inventory.pending(directory):
            break
    assert not state.store.inventory.pending(directory)
    with state.store.inventory.connection() as connection:
        assert connection.execute("SELECT count(*) FROM certificates").fetchone()[0] == 61


def test_index_failure_still_returns_and_replays_the_signed_chain(state, monkeypatch, caplog):
    directory = state.store.directory(state.authority_id)
    assert state.store.inventory.page(directory, "") == ([], None)
    assert not state.store.inventory.pending(directory)
    real_connection = state.store.inventory.connection

    def fail_index():
        raise OSError("synthetic-private-database-diagnostic")

    monkeypatch.setattr(state.store.inventory, "connection", fail_index)
    calls = []
    csr = leaf_csr()

    def sign(arguments):
        calls.append(arguments)
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(state.store.certificate(state.authority_id).subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(csr.extensions[0].value, False)
            .add_extension(x509.BasicConstraints(False, None), True)
            .sign(state.store.key(state.authority_id, {}), hashes.SHA384())
        )
        Path(arguments[3]).write_bytes(cert.public_bytes(Encoding.PEM))
        return ""

    monkeypatch.setattr(issuer, "run", sign)
    payload = {
        "request_id": uuid.uuid4().hex,
        "csr": csr.public_bytes(Encoding.PEM).decode(),
        "days": 1,
    }
    path = "/authorities/" + state.authority_id + "/issue"
    response = state.client.post(path, json=payload, headers=state.headers)
    assert response.status_code == 200
    assert state.client.post(path, json=payload, headers=state.headers).json == response.json
    status = state.client.get("/operations/" + payload["request_id"], headers=state.headers).json
    assert status["state"] == "complete"
    assert status["result"] == response.json
    assert len(calls) == 1
    assert "synthetic-private-database-diagnostic" not in caplog.text
    assert (directory / "inventory-dirty").is_file()
    monkeypatch.setattr(state.store.inventory, "connection", real_connection)
    assert state.store.inventory.page(directory, "") == ([response.json["pem"]], None)
    assert not (directory / "inventory-dirty").exists()


def test_ownership_conversion_preflights_and_resumes_controller_owned_database(
    tmp_path, monkeypatch
):
    import os

    from netadmin.ca_runtime import isolation
    from netadmin.ca_runtime.certificates import CAInputError

    home = tmp_path / "runtime"
    (home / "db").mkdir(parents=True)
    data = home / "db" / "data.sst"
    data.write_bytes(b"synthetic persistent issuer database")
    original_stat = Path.stat
    owners = {}
    changed = []

    def info(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        if path == home or home in path.parents:
            return os.stat_result((*value[:4], owners.get(path, 0), 0, *value[6:]))
        return value

    monkeypatch.setattr(Path, "stat", info)
    monkeypatch.setattr(Path, "lstat", lambda path: info(path, follow_symlinks=False))
    monkeypatch.setattr(
        isolation.os,
        "chown",
        lambda path, uid, gid: (owners.__setitem__(path, uid), changed.append(path)),
    )
    # A partial prior conversion may leave already converted regular files.
    owners[data] = 20000
    data.chmod(0o660)
    isolation._migrate_home(home, 20000)
    assert owners[home] == 20000
    assert owners[home / "db"] == 20000
    assert changed[-1] == home
    assert data not in changed
    assert data.read_bytes() == b"synthetic persistent issuer database"
    assert home.stat().st_mode & 0o777 == 0o770
    # A foreign owner is never silently adopted.
    owners[data] = 999
    with pytest.raises(CAInputError, match="non-controller-owned"):
        isolation._migrate_home(home, 20000)


def test_ownership_conversion_refuses_links_before_changing_any_file(tmp_path, monkeypatch):
    import os

    from netadmin.ca_runtime import isolation
    from netadmin.ca_runtime.certificates import CAInputError

    home = tmp_path / "runtime"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("must remain unchanged")
    link = home / "linked"
    link.symlink_to(outside)
    original_stat = Path.stat
    changed = []

    def info(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        return os.stat_result((*value[:4], 0, 0, *value[6:]))

    monkeypatch.setattr(Path, "stat", info)
    monkeypatch.setattr(Path, "lstat", lambda path: info(path, follow_symlinks=False))
    monkeypatch.setattr(isolation.os, "chown", lambda *args: changed.append(args))
    with pytest.raises(CAInputError, match="links or special"):
        isolation._migrate_home(home, 20000)
    assert not changed
    assert outside.read_text() == "must remain unchanged"
    link.unlink()
    os.link(outside, link)
    with pytest.raises(CAInputError, match="links or special"):
        isolation._migrate_home(home, 20000)
    assert not changed
