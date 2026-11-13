"""Stalled hostname lookups have bounded caller wait and bounded shared capacity."""

import socket
import time
from concurrent.futures import Future, ThreadPoolExecutor
from threading import BoundedSemaphore, Event, Lock

import pytest

from netadmin.services import dns as service

ADDRESSES = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.53", 53))]


def test_stalled_lookups_keep_slots_until_completion_and_then_recover(monkeypatch):
    released = Event()
    finished = Event()
    lock = Lock()
    completed = []
    calls = []
    slots = BoundedSemaphore(service._RESOLUTION_LIMIT)
    release_slot = slots.release

    def track_release():
        release_slot()
        with lock:
            completed.append(True)
            if len(completed) == service._RESOLUTION_LIMIT:
                finished.set()

    def stalled_lookup(host, port, **kwargs):
        assert (host, port, kwargs) == ("bind.test", 53, {"type": socket.SOCK_STREAM})
        with lock:
            calls.append(host)
        released.wait()
        return ADDRESSES

    def unexpected(*_args, **_kwargs):
        pytest.fail("No DNS write is allowed while hostname resolution is saturated")

    monkeypatch.setattr(slots, "release", track_release)
    monkeypatch.setattr(service, "_RESOLUTION_SLOTS", slots)
    monkeypatch.setattr(socket, "getaddrinfo", stalled_lookup)
    monkeypatch.setattr("dns.query.tcp", unexpected)
    with ThreadPoolExecutor(max_workers=service._RESOLUTION_LIMIT) as pool:
        monkeypatch.setattr(service, "_RESOLUTION_POOL", pool)
        try:
            for _ in range(service._RESOLUTION_LIMIT):
                deadline = time.monotonic() + 0.05
                started = time.monotonic()
                with pytest.raises(TimeoutError):
                    service._resolve_addresses("bind.test", 53, deadline)
                assert time.monotonic() - started < 1
            assert not slots.acquire(blocking=False)
            deadline = time.monotonic() + 9
            with pytest.raises(TimeoutError, match="resolver is busy"):
                service._resolve_addresses("bind.test", 53, deadline)
            bind = service.BindService("bind.test", "key", "")
            with pytest.raises(TimeoutError, match="resolver is busy"):
                bind.upsert("example.test", "host", "A", 300, "192.0.2.9")
            assert service._server_target("192.0.2.53", 53) == ("192.0.2.53", 10)
            released.set()
            assert finished.wait(2)
            assert len(calls) == service._RESOLUTION_LIMIT
            deadline = time.monotonic() + 2
            assert service._resolve_addresses("bind.test", 53, deadline) == ADDRESSES
        finally:
            released.set()  # A failed assertion must not leave resolver workers blocked.


def test_lookup_error_releases_capacity(monkeypatch):
    slots = BoundedSemaphore(1)

    def rejected(*_args, **_kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Synthetic missing hostname")

    monkeypatch.setattr(service, "_RESOLUTION_SLOTS", slots)
    monkeypatch.setattr(socket, "getaddrinfo", rejected)
    with ThreadPoolExecutor(max_workers=1) as pool:
        monkeypatch.setattr(service, "_RESOLUTION_POOL", pool)
        deadline = time.monotonic() + 2
        with pytest.raises(socket.gaierror):
            service._resolve_addresses("missing.invalid", 53, deadline)
    assert slots.acquire(blocking=False)
    slots.release()


def test_failed_submission_releases_capacity(monkeypatch):
    class UnavailablePool:
        def submit(self, *_args, **_kwargs):
            raise RuntimeError("Synthetic resolver shutdown")

    slots = BoundedSemaphore(1)
    monkeypatch.setattr(service, "_RESOLUTION_SLOTS", slots)
    monkeypatch.setattr(service, "_RESOLUTION_POOL", UnavailablePool())
    deadline = time.monotonic() + 2
    with pytest.raises(RuntimeError, match="resolver shutdown"):
        service._resolve_addresses("bind.test", 53, deadline)
    assert slots.acquire(blocking=False)
    slots.release()


def test_expired_deadline_does_not_submit_lookup(monkeypatch):
    class UnexpectedPool:
        def submit(self, *_args, **_kwargs):
            pytest.fail("An expired lookup must not enter the resolver pool")

    monkeypatch.setattr(service, "_RESOLUTION_POOL", UnexpectedPool())
    deadline = time.monotonic() - 1
    with pytest.raises(TimeoutError, match="resolution timed out"):
        service._resolve_addresses("bind.test", 53, deadline)


def test_deadline_expiring_during_submission_keeps_slot_until_lookup_finishes(monkeypatch):
    pending = Future()
    assert pending.set_running_or_notify_cancel()

    class PendingPool:
        def submit(self, *_args, **_kwargs):
            return pending

    slots = BoundedSemaphore(1)
    ticks = iter([1.0, 3.0])
    monkeypatch.setattr(service, "_RESOLUTION_SLOTS", slots)
    monkeypatch.setattr(service, "_RESOLUTION_POOL", PendingPool())
    monkeypatch.setattr(service.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="resolution timed out"):
        service._resolve_addresses("bind.test", 53, 2.0)
    assert not slots.acquire(blocking=False)
    pending.set_result(ADDRESSES)
    assert slots.acquire(blocking=False)
    slots.release()
