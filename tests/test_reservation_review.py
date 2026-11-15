"""Pool review must not write, lose scope, race native edits or steal active leases."""

import subprocess

import pytest

from netadmin.services import dhcp_files, kea_files
from tests.test_agent_endpoints import AUTH
from tests.test_agent_mutation_guards import dhcp_state  # noqa: F401

PAYLOAD = {
    "name": "reviewed",
    "mac": "aa:bb:cc:dd:ee:03",
    "address": "192.0.2.15",
    "network": "192.0.2.0",
}


def test_review_and_atomic_exclusion(dhcp_state):  # noqa: F811
    s = dhcp_state
    original = s.main.read_bytes()
    assert s.client.post("/reservations", json=PAYLOAD, headers=AUTH).status_code == 409
    plan = s.client.post("/reservations", json=PAYLOAD | {"preview": True}, headers=AUTH).json
    assert plan["after"] == [["192.0.2.10", "192.0.2.14"], ["192.0.2.16", "192.0.2.20"]]
    assert s.main.read_bytes() == original
    response = s.client.post(
        "/reservations",
        json=PAYLOAD | {"preview_token": plan["token"], "exclude_from_pools": True},
        headers=AUTH,
    )
    assert response.status_code == 200
    assert "range 192.0.2.16 192.0.2.20;" in s.main.read_text()
    assert "host reviewed" in s.managed.read_text()
    assert s.leases.read_text() == "retained synthetic leases"


@pytest.mark.parametrize("mutation", ["config", "address", "approval"])
def test_stale_or_modified_review_does_not_write(dhcp_state, mutation):  # noqa: F811
    s = dhcp_state
    token = s.client.post("/reservations", json=PAYLOAD | {"preview": True}, headers=AUTH).json[
        "token"
    ]
    payload = PAYLOAD | {"preview_token": token, "exclude_from_pools": True}
    if mutation == "config":
        s.main.write_text(s.main.read_text() + "# native edit\n")
    elif mutation == "address":
        payload["address"] = "192.0.2.16"
    else:
        payload["exclude_from_pools"] = False
    before = s.main.read_bytes()
    assert s.client.post("/reservations", json=payload, headers=AUTH).status_code == 409
    assert s.main.read_bytes() == before
    assert s.managed.read_bytes() == b""


def test_reload_failure_rolls_back_pool_and_reservation(dhcp_state, monkeypatch):  # noqa: F811
    s = dhcp_state
    s.client.application.config["DHCP_RELOAD"] = ["reload"]
    token = s.client.post("/reservations", json=PAYLOAD | {"preview": True}, headers=AUTH).json[
        "token"
    ]
    before = s.main.read_bytes()

    def run(command, **_kwargs):
        if command == ["reload"]:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr("netadmin.agents.dhcp.subprocess.run", run)
    response = s.client.post(
        "/reservations",
        json=PAYLOAD | {"preview_token": token, "exclude_from_pools": True},
        headers=AUTH,
    )
    assert response.status_code == 500
    assert s.main.read_bytes() == before
    assert s.managed.read_bytes() == b""


def test_selected_subnet_and_live_lease_are_enforced(dhcp_state):  # noqa: F811
    s = dhcp_state
    assert (
        s.client.post(
            "/reservations", json=PAYLOAD | {"network": "198.51.100.0"}, headers=AUTH
        ).status_code
        == 409
    )
    s.leases.write_text(
        "lease 192.0.2.15 { binding state active; hardware ethernet aa:bb:cc:dd:ee:09; }"
    )
    assert (
        s.client.post("/reservations", json=PAYLOAD | {"preview": True}, headers=AUTH).status_code
        == 409
    )


def test_isc_pool_scope_comments_and_options_survive():
    text = (
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n"
        " pool { allow known-clients; range 192.0.2.10 192.0.2.20; }\n"
        " # range 192.0.2.1 192.0.2.99;\n option routers 192.0.2.1;\n}"
    )
    updated = dhcp_files.exclude_address(text, "192.0.2.0", "192.0.2.15")
    assert (
        "pool { allow known-clients; range 192.0.2.10 192.0.2.14; range 192.0.2.16 192.0.2.20; }"
        in updated
    )
    assert "# range 192.0.2.1 192.0.2.99;" in updated
    assert "option routers 192.0.2.1;" in updated


def test_kea_cidr_pool_metadata_survives():
    text = '{"subnet":"192.0.2.0/24","pools":[{"pool":"192.0.2.0/24","client-class":"known"}]}'
    updated = kea_files.exclude_address(text, "192.0.2.0", "192.0.2.15")
    assert updated.count('"client-class": "known"') == 2
    assert kea_files.subnets(updated)[0]["ranges"] == [
        ["192.0.2.0", "192.0.2.14"],
        ["192.0.2.16", "192.0.2.255"],
    ]


def test_unsupported_allocations_cannot_bypass_pool_review():
    from netadmin.agents.reservation_review import select_subnet

    text = "subnet 192.0.2.0 netmask 255.255.255.0 { range dynamic-bootp 192.0.2.10 192.0.2.20; }"
    inventory = dhcp_files.subnets(text)
    with pytest.raises(ValueError, match="natively"):
        select_subnet(inventory, "192.0.2.15", "192.0.2.0")
    text = '{"subnet":"192.0.2.0/24",<?include "pools.json"?>}'
    with pytest.raises(ValueError, match="natively"):
        select_subnet(kea_files.subnets(text), "192.0.2.15", "192.0.2.0")


def test_pool_edit_cannot_reintroduce_reserved_address(dhcp_state):  # noqa: F811
    s = dhcp_state
    response = s.client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [["192.0.2.2", "192.0.2.20"]],
            "options": {},
        },
    )
    assert response.status_code == 409
    assert "reserved IP 192.0.2.5" in response.json["error"]


def test_review_ui_preserves_scope_and_requires_explicit_approval(tmp_path):
    from types import SimpleNamespace

    from tests.test_multi_service_ui import admin_client

    app, client = admin_client(tmp_path)
    calls = []
    plan = {
        "item": PAYLOAD,
        "network": "192.0.2.0",
        "before": [["192.0.2.10", "192.0.2.20"]],
        "after": [["192.0.2.10", "192.0.2.14"], ["192.0.2.16", "192.0.2.20"]],
        "pool_change": True,
        "token": "123.signature",
    }

    def post(path, payload):
        calls.append((path, payload))
        return plan

    subnet = {"network": "192.0.2.0", "netmask": "255.255.255.0", "ranges": [], "options": {}}
    app.extensions["netadmin_dhcp"] = SimpleNamespace(
        post=post,
        get=lambda path: [subnet] if path == "configuration" else [],
        read_only=lambda: False,
    )
    response = client.post("/dhcp", data=PAYLOAD | {"action": "review"})
    assert response.status_code == 200
    assert "Dynamic pools after" in response.text
    assert 'value="123.signature"' in response.text
    assert calls[-1][1]["preview"] is True
    response = client.post(
        "/dhcp", data=PAYLOAD | {"preview_token": "123.signature", "exclude_from_pools": "y"}
    )
    assert response.status_code == 302
    assert calls[-1][1]["exclude_from_pools"] is True


@pytest.mark.parametrize("phase", ["review", "install"])
def test_unexpected_configuration_errors_are_redacted_and_leave_files_unchanged(
    dhcp_state,  # noqa: F811
    monkeypatch,
    phase,
):
    state = dhcp_state
    payload = PAYLOAD | {"preview": True}
    if phase == "install":
        token = state.client.post("/reservations", json=payload, headers=AUTH).json["token"]
        payload = PAYLOAD | {"preview_token": token, "exclude_from_pools": True}
    original = state.main.read_bytes()

    def failure(*_args, **_kwargs):
        raise ValueError("synthetic-private-diagnostic /private/config/path SECRET-MATERIAL")

    target = "_all_subnets" if phase == "review" else "_validate_live"
    monkeypatch.setattr("netadmin.agents.dhcp." + target, failure)
    response = state.client.post("/reservations", json=payload, headers=AUTH)
    assert response.status_code == 409
    assert "synthetic-private-diagnostic" not in response.text
    assert "/private/config/path" not in response.text
    assert "SECRET-MATERIAL" not in response.text
    assert state.main.read_bytes() == original
    assert state.managed.read_bytes() == b""


def test_safe_scope_error_remains_actionable(dhcp_state):  # noqa: F811
    response = dhcp_state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview": True,
            "network": "198.51.100.0",
        },
    )
    assert response.status_code == 409
    assert "does not belong to the selected subnet/VLAN" in response.json["error"]


def test_unknown_validation_code_never_echoes_diagnostics():
    from netadmin.agents.reservation_review import ReservationInputError

    error = ReservationInputError("synthetic-private-diagnostic")
    assert "synthetic-private-diagnostic" not in error.safe_message()
