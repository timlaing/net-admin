"""DNS transport accepts hostnames without passing them to dnspython."""

import socket

import dns.flags
import dns.message
import dns.zone
import pytest

from netadmin.services.dns import BindService


def perform(service: BindService, operation: str) -> None:
    """Exercise every direct Bind network operation."""
    if operation == "records":
        service.records("example.test")
    elif operation == "upsert":
        service.upsert("example.test", "host", "A", 300, "192.0.2.9")
    elif operation == "delete":
        service.delete("example.test", "host", "A")
    elif operation == "addresses":
        service.addresses("example.test", "host")
    else:
        service.restore_addresses("example.test", "host", [], expected="192.0.2.9")


@pytest.mark.parametrize("operation", ["records", "upsert", "delete", "addresses", "restore"])
@pytest.mark.parametrize(
    ("server", "resolved", "family", "scope"),
    [
        ("netadmin-dns", "192.0.2.53", socket.AF_INET, 0),
        ("netadmin-dns", "2001:db8::53", socket.AF_INET6, 0),
        ("netadmin-dns", "fe80::53", socket.AF_INET6, 2),
        ("192.0.2.53", "192.0.2.53", socket.AF_INET, 0),
        ("2001:db8::53", "2001:db8::53", socket.AF_INET6, 0),
        ("fe80::53%eth0", "fe80::53%eth0", socket.AF_INET6, 0),
    ],
)
def test_network_operations_resolve_hostnames(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    server: str,
    resolved: str,
    family: int,
    scope: int,
) -> None:
    lookups = []
    calls = []

    def resolve(host, port, **kwargs):
        lookups.append((host, port, kwargs))
        address = (resolved, port, 0, scope) if family == socket.AF_INET6 else (resolved, port)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]

    def tcp(query, where, **kwargs):
        calls.append((where, kwargs))
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        return response

    def xfr(where, _zone, **kwargs):
        calls.append((where, kwargs))
        return iter(())

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dns.query, "tcp", tcp)
    monkeypatch.setattr(dns.query, "xfr", xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _: dns.zone.Zone("example.test"))
    service = BindService(server, "key", "", port=5353)
    perform(service, operation)
    expected = f"{resolved}%{scope}" if scope else resolved
    assert calls[0][0] == expected
    assert calls[0][1]["port"] == 5353
    assert service.server == server
    assert lookups == (
        [(server, 5353, {"type": socket.SOCK_STREAM})] if server == "netadmin-dns" else []
    )


def test_hostname_is_resolved_again_after_container_address_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    addresses = iter(["192.0.2.53", "192.0.2.54"])
    calls = []

    def resolve(_host, port, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (next(addresses), port))
        ]

    def xfr(where, _zone, **_kwargs):
        calls.append(where)
        return iter(())

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dns.query, "xfr", xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _: dns.zone.Zone("example.test"))
    service = BindService("netadmin-dns", "key", "")
    service.records("example.test")
    service.records("example.test")
    assert calls == ["192.0.2.53", "192.0.2.54"]


@pytest.mark.parametrize("operation", ["records", "upsert", "delete", "addresses", "restore"])
def test_resolution_failure_does_not_contact_bind(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    def resolve(*_args, **_kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name not found")

    def unexpected(*_args, **_kwargs):
        pytest.fail("DNS transport must not run after resolution fails")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dns.query, "tcp", unexpected)
    monkeypatch.setattr(dns.query, "xfr", unexpected)
    service = BindService("missing.invalid", "key", "")
    error = RuntimeError if operation == "addresses" else socket.gaierror
    with pytest.raises(error):
        perform(service, operation)


@pytest.mark.parametrize("operation", ["records", "upsert", "delete", "addresses", "restore"])
@pytest.mark.parametrize("first_error", [ConnectionRefusedError, TimeoutError])
def test_dual_stack_hostname_uses_reachable_address_before_dns_request(
    monkeypatch: pytest.MonkeyPatch, operation: str, first_error: type[OSError]
) -> None:
    attempts = []
    sockets = []
    calls = []
    clock = [0.0]

    class Connection:
        def __init__(self, family, *_args):
            self.family = family
            self.closed = False
            sockets.append(self)

        def settimeout(self, timeout):
            assert 0 < timeout <= 0.5

        def connect(self, address):
            attempts.append(address)
            if self.family == socket.AF_INET6:
                clock[0] += 0.5
                raise first_error("Bind only listens on IPv4")
            self.address = address

        def getpeername(self):
            return self.address

        def close(self):
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def resolve(_host, port, *_args, **_kwargs):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.53", port)),
        ]

    def tcp(query, where, **kwargs):
        assert kwargs["timeout"] == 8.5
        calls.append(where)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        return response

    def xfr(where, _zone, **kwargs):
        assert kwargs["lifetime"] == 8.5
        calls.append(where)
        return iter(())

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", Connection)
    monkeypatch.setattr("netadmin.services.dns.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(dns.query, "tcp", tcp)
    monkeypatch.setattr(dns.query, "xfr", xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _: dns.zone.Zone("example.test"))
    perform(BindService("bind.test", "key", "", port=5353), operation)
    assert attempts == [("::1", 5353, 0, 0), ("192.0.2.53", 5353)]
    assert all(connection.closed for connection in sockets)
    assert calls == ["192.0.2.53"]


@pytest.mark.parametrize("phase", ["selection", "resolution", "unreachable"])
def test_address_selection_budget_failures_do_not_send_dns_requests(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    ticks = iter([0.0, 0.0, 3.0] if phase == "selection" else [0.0, 10.0])

    def resolve(_host, port, **_kwargs):
        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.53", port))
        return [address] if phase == "resolution" else [address, address]

    class Unreachable:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def settimeout(self, _timeout):
            pass

        def connect(self, _address):
            raise ConnectionRefusedError("No Bind listener")

    def unexpected(*_args, **_kwargs):
        pytest.fail("DNS transport must not run after address selection fails")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", Unreachable)
    monkeypatch.setattr(dns.query, "xfr", unexpected)
    monkeypatch.setattr(
        "netadmin.services.dns.time.monotonic",
        lambda: 0.0 if phase == "unreachable" else next(ticks),
    )
    with pytest.raises(OSError):
        BindService("bind.test", "key", "").records("example.test")


def test_update_is_not_retried_after_dns_transport_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def tcp(_query, where, **_kwargs):
        calls.append(where)
        raise TimeoutError("Response lost after sending update")

    monkeypatch.setattr(dns.query, "tcp", tcp)
    service = BindService("192.0.2.53", "key", "")
    with pytest.raises(TimeoutError):
        service.upsert("example.test", "host", "A", 300, "192.0.2.9")
    assert calls == ["192.0.2.53"]
