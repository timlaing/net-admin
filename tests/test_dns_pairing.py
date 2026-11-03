"""Authoritative snapshots and value-dependent rollback preserve concurrent writers."""

from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rrset
import pytest

from netadmin.services.dns import AgentDnsService, BindService, DnsRecord
from tests.test_dns_agent import AUTH, agent


def answer(query, *, code=dns.rcode.NOERROR, authoritative=True, addresses=()):
    response = dns.message.make_response(query)
    response.set_rcode(code)
    if authoritative:
        response.flags |= dns.flags.AA
    if addresses:
        response.answer.append(dns.rrset.from_text("NODE.example.test.", 0, "IN", "A", *addresses))
    return response


def test_owner_query_uses_authoritative_tcp_not_axfr_and_matches_dns_case(monkeypatch):
    bind = BindService("192.0.2.53", "", "")
    calls = []

    def exchange(query, server, **kwargs):
        calls.append(query)
        assert server == "192.0.2.53"
        assert kwargs == {"port": 53, "timeout": 10}
        assert query.flags & dns.flags.RD == 0
        return answer(query, addresses=("192.0.2.10", "192.0.2.11"))

    monkeypatch.setattr("dns.query.tcp", exchange)
    monkeypatch.setattr(bind, "records", lambda *_args: pytest.fail("AXFR must not be used"))
    assert bind.addresses("example.test", "NoDe") == [
        DnsRecord("NoDe", 0, "A", "192.0.2.10"),
        DnsRecord("NoDe", 0, "A", "192.0.2.11"),
    ]
    assert len(calls) == 1
    with pytest.raises(ValueError, match="selected zone"):
        bind.addresses("example.test", "outside.invalid.")
    assert len(calls) == 1


@pytest.mark.parametrize("code", [dns.rcode.NOERROR, dns.rcode.NXDOMAIN])
def test_authoritative_absence_is_distinct_from_failed_snapshot(monkeypatch, code):
    bind = BindService("192.0.2.53", "", "")
    monkeypatch.setattr("dns.query.tcp", lambda query, *_a, **_k: answer(query, code=code))
    assert bind.addresses("example.test", "node") == []


@pytest.mark.parametrize(
    "mode", ["refused", "servfail", "non-authoritative", "timeout", "alias", "unsigned"]
)
def test_unknown_prior_state_never_mutates_dns(monkeypatch, mode):
    bind = BindService("192.0.2.53", "test", "YWJj" if mode == "unsigned" else "")
    writes = []
    monkeypatch.setattr(bind, "upsert", lambda *args: writes.append(args))

    def exchange(query, *_args, **_kwargs):
        if mode == "timeout":
            raise dns.exception.Timeout()
        response = answer(query, authoritative=mode != "non-authoritative")
        if mode in {"refused", "servfail"}:
            response.set_rcode(dns.rcode.REFUSED if mode == "refused" else dns.rcode.SERVFAIL)
        if mode == "unsigned":
            response.tsig = None
        if mode == "alias":
            response.answer.append(
                dns.rrset.from_text(
                    "node.example.test.", 300, "IN", "CNAME", "target.example.test."
                )
            )
        return response

    monkeypatch.setattr("dns.query.tcp", exchange)
    with pytest.raises(RuntimeError):
        bind.add_host("node", "192.0.2.9", "example.test", "2.0.192.in-addr.arpa", 600)
    assert not writes


def test_rollback_preserves_zero_ttl_and_requires_exact_written_rrset(monkeypatch):
    bind = BindService("192.0.2.53", "", "")
    messages = []

    def exchange(query, *_args, **_kwargs):
        if query.opcode() == dns.opcode.QUERY:
            return answer(query, addresses=("192.0.2.10", "192.0.2.11"))
        messages.append(query)
        return SimpleNamespace(rcode=lambda: dns.rcode.NXRRSET)

    def upsert(*args):
        if args[2] == "PTR":
            raise OSError("synthetic reverse failure")

    monkeypatch.setattr("dns.query.tcp", exchange)
    monkeypatch.setattr(bind, "upsert", upsert)
    with pytest.raises(RuntimeError, match="rollback failed"):
        bind.add_host("NoDe", "192.0.2.9", "example.test", "2.0.192.in-addr.arpa", 600)
    assert len(messages) == 1
    prerequisite = messages[0].prerequisite
    assert {item.to_text() for rrset in prerequisite for item in rrset} == {"192.0.2.9"}
    assert all(rrset.rdclass == 1 for rrset in prerequisite)
    restored = [rrset for rrset in messages[0].authority if len(rrset)]
    assert {rrset.ttl for rrset in restored} == {0}
    assert {item.to_text() for rrset in restored for item in rrset} == {"192.0.2.10", "192.0.2.11"}


def test_empty_snapshot_rollback_is_conditional_delete(monkeypatch):
    bind = BindService("192.0.2.53", "", "")
    messages = []
    monkeypatch.setattr(
        "dns.query.tcp",
        lambda update, *_a, **_k: messages.append(update) or SimpleNamespace(rcode=lambda: 0),
    )
    bind.restore_addresses("example.test", "node", [], expected="192.0.2.9")
    assert len(messages[0].prerequisite) == 1
    assert not any(len(rrset) for rrset in messages[0].authority)


@pytest.mark.parametrize("count", [100, 101])
def test_agent_targeted_snapshot_and_large_zero_ttl_restore(tmp_path, monkeypatch, count):
    client, _main = agent(tmp_path, monkeypatch)
    calls = []
    addresses = [f"192.0.2.{index}" for index in range(1, count + 1)]
    snapshot = [DnsRecord("NoDe", 0, "A", address) for address in addresses]
    monkeypatch.setattr(BindService, "addresses", lambda _self, zone, name: snapshot)
    monkeypatch.setattr(
        BindService,
        "restore_addresses",
        lambda _self, *args, **kwargs: calls.append((args, kwargs)),
    )
    response = client.get("/records/addresses?zone=existing.example&name=NoDe", headers=AUTH)
    assert response.status_code == 200
    assert len(response.json) == count
    payload = {
        "zone": "existing.example",
        "name": "NoDe",
        "record_type": "A",
        "ttl": 0,
        "values": addresses,
        "expected": "192.0.2.9",
    }
    assert client.post("/records", headers=AUTH, json=payload).status_code == 200
    assert calls == [(("existing.example", "NoDe", snapshot), {"expected": "192.0.2.9"})]
    assert (
        client.post(
            "/records", headers=AUTH, json={**payload, "values": [], "expected": "invalid"}
        ).status_code
        == 400
    )
    assert len(calls) == 1
    assert (
        client.post(
            "/records",
            headers=AUTH,
            json={**payload, "value": "192.0.2.10", "values": [], "expected": False},
        ).status_code
        == 400
    )
    assert len(calls) == 1
    assert (
        client.post(
            "/records",
            headers=AUTH,
            json={
                "zone": "existing.example",
                "name": "node",
                "record_type": "A",
                "ttl": 0,
                "value": "192.0.2.9",
            },
        ).status_code
        == 400
    )


def test_agent_client_preserves_snapshot_and_expected_value():
    calls = []
    bind = AgentDnsService(
        SimpleNamespace(
            get=lambda path: (
                calls.append(path)
                or [{"name": "NoDe", "ttl": 0, "record_type": "A", "value": "192.0.2.10"}]
            ),
            post=lambda *args: calls.append(args),
        )
    )
    snapshot = bind.addresses("example.test", "NoDe")
    assert calls[0] == "records/addresses?zone=example.test&name=NoDe"
    bind.restore_addresses("example.test", "NoDe", snapshot, expected="192.0.2.9")
    assert calls[-1][1]["expected"] == "192.0.2.9"
    assert calls[-1][1]["ttl"] == 0
