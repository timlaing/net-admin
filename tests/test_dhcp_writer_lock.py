"""All DHCP writers serialize configuration reads through activation and rollback."""

import fcntl
import multiprocessing
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from netadmin.agents import dhcp
from netadmin.agents.dhcp_state import configuration_lock
from netadmin.services import dhcp_files
from tests.test_agent_endpoints import AUTH
from tests.test_agent_mutation_guards import dhcp_state  # noqa: F401
from tests.test_reservation_review import PAYLOAD


@pytest.fixture
def state(dhcp_state):  # noqa: F811
    return dhcp_state


def _process_lock(main, ready, acquired):
    ready.set()
    with configuration_lock(Path(main)):
        acquired.set()


def test_configuration_lock_serializes_independent_processes(tmp_path):
    main = tmp_path / "dhcpd.conf"
    context = multiprocessing.get_context("spawn")
    ready, acquired = context.Event(), context.Event()
    worker = context.Process(target=_process_lock, args=(str(main), ready, acquired))
    try:
        with configuration_lock(main):
            worker.start()
            assert ready.wait(10)
            assert not acquired.wait(0.1)
        assert acquired.wait(10)
        worker.join(10)
        assert worker.exitcode == 0
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(10)


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("/reservations", PAYLOAD | {"address": "192.0.2.6"}),
        ("/reservations/delete", {"name": "legacy"}),
        ("/configuration", {"network": "192.0.2.0", "ranges": [], "options": {}}),
        ("/subnets", {"cidr": "198.51.100.0/24"}),
        ("/subnets/delete", {"network": "192.0.2.0"}),
    ],
)
def test_every_writer_waits_before_reading_configuration(state, monkeypatch, endpoint, payload):
    started, read = threading.Event(), threading.Event()
    for name in ("_configuration_snapshot", "_all_subnets", "_current"):
        original = getattr(dhcp, name)

        def observe(*args, operation=original, **kwargs):
            read.set()
            return operation(*args, **kwargs)

        monkeypatch.setattr(dhcp, name, observe)

    def request():
        started.set()
        with state.client.application.test_client() as client:
            return client.post(endpoint, headers=AUTH, json=payload).status_code

    with ThreadPoolExecutor(max_workers=1) as pool:
        with configuration_lock(state.main):
            result = pool.submit(request)
            assert started.wait(5)
            assert not read.wait(0.1)
        assert result.result(timeout=10) in {200, 201}
    assert read.is_set()


def test_concurrent_approved_saves_do_not_interleave_snapshots_or_files(state, monkeypatch):
    second = PAYLOAD | {"name": "second", "mac": "aa:bb:cc:dd:ee:04", "address": "192.0.2.16"}
    tokens = [
        state.client.post("/reservations", headers=AUTH, json=item | {"preview": True}).json[
            "token"
        ]
        for item in (PAYLOAD, second)
    ]
    entered, release, started, second_snapshot = (threading.Event() for _ in range(4))
    snapshot = dhcp._configuration_snapshot

    def observe(*args):
        if threading.current_thread().name == "second-writer":
            second_snapshot.set()
        return snapshot(*args)

    def validate(_main):
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr(dhcp, "_configuration_snapshot", observe)
    monkeypatch.setattr(dhcp, "_validate_live", validate)
    results = {}

    def save(name, item, token):
        if name == "second":
            started.set()
        with state.client.application.test_client() as client:
            results[name] = client.post(
                "/reservations",
                headers=AUTH,
                json=item
                | {
                    "preview_token": token,
                    "exclude_from_pools": True,
                },
            ).status_code

    first = threading.Thread(target=save, args=("first", PAYLOAD, tokens[0]))
    other = threading.Thread(target=save, name="second-writer", args=("second", second, tokens[1]))
    first.start()
    try:
        assert entered.wait(5)
        other.start()
        assert started.wait(5)
        assert not second_snapshot.wait(0.1)
    finally:
        release.set()
        first.join(10)
        if other.ident is not None:
            other.join(10)
    assert not first.is_alive()
    assert not other.is_alive()
    assert results == {"first": 200, "second": 409}
    assert [item["name"] for item in dhcp.parse_reservations(state.managed.read_text())] == [
        "reviewed"
    ]
    plan = state.client.post("/reservations", headers=AUTH, json=second | {"preview": True}).json
    response = state.client.post(
        "/reservations",
        headers=AUTH,
        json=second
        | {
            "preview_token": plan["token"],
            "exclude_from_pools": True,
        },
    )
    assert response.status_code == 200
    assert {item["name"] for item in dhcp.parse_reservations(state.managed.read_text())} == {
        "reviewed",
        "second",
    }
    assert dhcp_files.subnets(state.main.read_text())[0]["ranges"] == [
        ["192.0.2.10", "192.0.2.14"],
        ["192.0.2.17", "192.0.2.20"],
    ]


def test_lock_remains_held_during_reload_verification_and_rollback(state, monkeypatch):
    state.client.application.config["DHCP_RELOAD"] = ["synthetic-reload"]
    lock = state.main.parent / ".netadmin-dhcp.lock"
    phases = []

    def assert_locked(phase):
        descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            phases.append(phase)
        finally:
            os.close(descriptor)

    def run(command, **_kwargs):
        if command == ["synthetic-reload"]:
            assert_locked("reload")

    def conflict(_item):
        assert_locked("verify")
        raise dhcp.LeaseConflict("synthetic post-reload conflict")

    monkeypatch.setattr(dhcp.subprocess, "run", run)
    monkeypatch.setattr(dhcp, "_verify_reservation_lease", conflict)
    before = state.main.read_bytes()
    response = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"address": "192.0.2.6"}
    )
    assert response.status_code == 409
    assert phases == ["reload", "verify", "reload"]
    assert state.main.read_bytes() == before
    assert state.managed.read_bytes() == b""
    with configuration_lock(state.main):
        assert lock.stat().st_mode & 0o777 == 0o600


def test_lock_rejects_symlink_and_special_file(tmp_path):
    main = tmp_path / "dhcpd.conf"
    lock = tmp_path / ".netadmin-dhcp.lock"
    protected = tmp_path / "protected"
    protected.write_bytes(b"unchanged")
    lock.symlink_to(protected)
    with pytest.raises(OSError), configuration_lock(main):
        pytest.fail("A symlink must not be locked")
    assert protected.read_bytes() == b"unchanged"
    lock.unlink()
    os.mkfifo(lock, 0o600)
    with pytest.raises(ValueError), configuration_lock(main):
        pytest.fail("A FIFO must not be locked")
