"""Subnet edits reject lossy or invalid input before calling the agent."""

import pytest

from netadmin.services.dhcp_files import subnets, update_subnet
from netadmin.subnet_editor import subnet_payload


@pytest.mark.parametrize(
    "pools,options",
    [
        ("192.0.2.1", ""),
        ("192.0.2.20-192.0.2.10", ""),
        ("198.51.100.1-198.51.100.2", ""),
        ("192.0.2.0-192.0.2.5", ""),
        ("192.0.2.10-192.0.2.255", ""),
        ("192.0.2.10-192.0.2.20\n192.0.2.20-192.0.2.30", ""),
        ("", "routers"),
        ("", "routers="),
        ("", "routers=a\nrouters=b"),
    ],
)
def test_invalid_subnet_input(pools, options):
    with pytest.raises(ValueError):
        subnet_payload("192.0.2.0", "255.255.255.0", pools, options)


def test_isc_text_options_keep_quotes_when_editing():
    original = 'subnet 192.0.2.0 netmask 255.255.255.0 {\n option domain-name "lan.example";\n}\n'
    subnet = subnets(original)[0]
    assert subnet["options"]["domain-name"] == '"lan.example"'
    result = update_subnet(original, "192.0.2.0", [], subnet["options"])
    assert 'option domain-name "lan.example";' in result


@pytest.mark.parametrize(
    "read_only,expected",
    [(True, "Read-only"), (False, "Writable"), ("false", "Unknown"), (None, "Unknown")],
)
def test_advertised_access_mode(monkeypatch, read_only, expected):
    from netadmin.services.agents import AgentClient

    client = AgentClient("https://synthetic", "synthetic")
    monkeypatch.setattr(client, "get", lambda *args, **kwargs: {"read_only": read_only})
    assert client.access_mode() == expected
