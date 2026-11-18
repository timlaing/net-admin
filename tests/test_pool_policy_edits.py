"""Scoped pool policy must not be bypassed by whole-subnet rewrite operations."""

import pytest

from netadmin.agents import dhcp
from netadmin.services import dhcp_files
from tests.test_agent_endpoints import AUTH
from tests.test_agent_mutation_guards import dhcp_state  # noqa: F401
from tests.test_reservation_review import PAYLOAD


@pytest.fixture
def state(dhcp_state):  # noqa: F811
    return dhcp_state


def config(pool, shared):
    subnet = f"subnet 192.0.2.0 netmask 255.255.255.0 {{\n{pool}\n}}"
    return f"shared-network office {{\n{subnet}\n}}" if shared else subnet


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize(
    "pool",
    [
        "pool { allow known-clients; range 192.0.2.10 192.0.2.20; }",
        "pool {\n allow known-clients;\n range 192.0.2.10 192.0.2.20;\n}",
        "POOL { allow known-clients; RANGE 192.0.2.10 192.0.2.20; }",
    ],
)
@pytest.mark.parametrize("ranges", [[], [["192.0.2.30", "192.0.2.40"]]])
def test_scoped_pool_rewrite_is_rejected_for_every_subnet_shape(state, pool, shared, ranges):
    text = config(pool, shared) + f'\ninclude "{state.managed}";\n'
    state.main.write_text(text)
    parsed = dhcp_files.subnets(text)[0]
    assert parsed["pool_edit_supported"] is False
    assert parsed.get("pool_review_supported", True)
    with pytest.raises(dhcp_files.PoolScopeEditError):
        dhcp_files.update_subnet(text, "192.0.2.0", ranges, {})
    response = state.client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": ranges,
            "options": {},
        },
    )
    assert response.status_code == 409
    assert "native editor" in response.json["error"]
    assert state.main.read_text() == text
    assert state.managed.read_bytes() == b""


def test_options_only_edit_cannot_rewrite_an_acl_pool(state):
    text = config("pool { allow known-clients; range 192.0.2.10 192.0.2.20; }", False)
    state.main.write_text(text + f'\ninclude "{state.managed}";\n')
    before = state.main.read_bytes()
    response = state.client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [["192.0.2.10", "192.0.2.20"]],
            "options": {"routers": "192.0.2.1"},
        },
    )
    assert response.status_code == 409
    assert state.main.read_bytes() == before


def test_reservation_exclusion_still_preserves_scoped_acl(state):
    state.main.write_text(
        config("pool { allow known-clients; range 192.0.2.10 192.0.2.20; }", False)
        + f'\ninclude "{state.managed}";\n'
    )
    preview = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True})
    assert preview.status_code == 200
    saved = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": preview.json["token"],
            "exclude_from_pools": True,
        },
    )
    assert saved.status_code == 200
    assert (
        "pool { allow known-clients; range 192.0.2.10 192.0.2.14; range 192.0.2.16 192.0.2.20; }"
        in state.main.read_text()
    )


@pytest.mark.parametrize(
    "text",
    [
        "subnet 192.0.2.0 netmask 255.255.255.0 { range 192.0.2.10 192.0.2.20; }",
        "SUBNET 192.0.2.0 NETMASK 255.255.255.0 { RANGE 192.0.2.10 192.0.2.20; }",
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n range 192.0.2.15;\n}",
    ],
)
@pytest.mark.parametrize("ranges", [[], [["192.0.2.30", "192.0.2.40"]]])
def test_unscoped_inline_and_multiline_ranges_are_actually_removed(text, ranges):
    updated = dhcp_files.update_subnet(text, "192.0.2.0", ranges, {})
    assert dhcp_files.subnets(updated)[0]["ranges"] == ranges


def test_quoted_or_commented_pool_examples_do_not_block_or_get_rewritten():
    text = (
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n"
        " # pool { range 192.0.2.10 192.0.2.20; }\n"
        ' option domain-name "pool { range 192.0.2.50 192.0.2.60; }";\n'
        " range 192.0.2.10 192.0.2.20;\n}"
    )
    assert dhcp_files.subnets(text)[0].get("pool_edit_supported", True)
    updated = dhcp_files.update_subnet(
        text,
        "192.0.2.0",
        [],
        {
            "domain-name": '"pool { range 192.0.2.50 192.0.2.60; }"',
        },
    )
    assert "# pool { range 192.0.2.10 192.0.2.20; }" in updated
    assert '"pool { range 192.0.2.50 192.0.2.60; }"' in updated
    assert dhcp_files.subnets(updated)[0]["ranges"] == []


def test_late_native_pool_change_is_rejected_without_raw_exception_text(state, monkeypatch):
    update = dhcp._update_subnet

    def native_edit(_text, network, ranges, options):
        return update(
            config("pool { allow known-clients; range 192.0.2.10 192.0.2.20; }", False),
            network,
            ranges,
            options,
        )

    monkeypatch.setattr(dhcp, "_update_subnet", native_edit)
    before = state.main.read_bytes()
    response = state.client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [],
            "options": {},
        },
    )
    assert response.status_code == 409
    assert state.main.read_bytes() == before
