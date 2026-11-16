"""CodeRabbit safety regressions: lease history, signed snapshots and ISC syntax."""

from pathlib import Path

import pytest

from netadmin.agents import dhcp
from netadmin.agents.common import ConfigurationChanged, validated_transaction
from netadmin.services import dhcp_files
from tests.test_agent_endpoints import AUTH
from tests.test_agent_mutation_guards import dhcp_state  # noqa: F401
from tests.test_reservation_review import PAYLOAD


@pytest.fixture
def state(dhcp_state):  # noqa: F811
    return dhcp_state


def lease(mac: str, status: str = "active") -> str:
    return f"lease 192.0.2.15 {{ binding state {status}; hardware ethernet {mac}; }}\n"


@pytest.mark.parametrize(
    "latest,expected",
    [
        (lease("aa:bb:cc:dd:ee:09", "free"), 200),
        (lease(PAYLOAD["mac"]), 200),
        (lease("aa:bb:cc:dd:ee:08"), 409),
    ],
)
def test_last_lease_declaration_controls_conflict(state, latest, expected):
    state.leases.write_text(lease("aa:bb:cc:dd:ee:09") + latest)
    response = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True})
    assert response.status_code == expected
    assert state.managed.read_bytes() == b""


def test_preview_parses_the_signed_snapshot_not_later_native_edits(state, monkeypatch):
    capture = dhcp._configuration_snapshot
    original = state.main.read_bytes()

    def snapshot(*args):
        result = capture(*args)
        state.main.write_bytes(original.replace(b"192.0.2.20", b"192.0.2.30"))
        return result

    monkeypatch.setattr(dhcp, "_configuration_snapshot", snapshot)
    preview = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True})
    assert preview.status_code == 200
    assert preview.json["before"] == [["192.0.2.10", "192.0.2.20"]]
    monkeypatch.setattr(dhcp, "_configuration_snapshot", capture)
    saved = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": preview.json["token"],
            "exclude_from_pools": True,
        },
    )
    assert saved.status_code == 409
    assert state.managed.read_bytes() == b""


def test_snapshot_include_graph_comes_from_captured_bytes(state, monkeypatch):
    old_include = state.main.parent / "old.conf"
    new_include = state.main.parent / "new.conf"
    old_include.write_text("# old snapshot member\n")
    new_include.write_text("# new native member\n")
    state.main.write_text(state.main.read_text() + f'include "{old_include}";\n')
    read = Path.read_bytes

    def changing_read(path):
        content = read(path)
        if path == state.main:
            path.write_bytes(content.replace(str(old_include).encode(), str(new_include).encode()))
        return content

    monkeypatch.setattr(Path, "read_bytes", changing_read)
    captured = dhcp._configuration_snapshot(state.main, state.managed)
    assert old_include in captured
    assert new_include not in captured


def test_snapshot_reservation_conflicts_ignore_later_native_content(state, monkeypatch):
    capture = dhcp._configuration_snapshot

    def snapshot(*args):
        result = capture(*args)
        state.main.write_text(
            state.main.read_text()
            + "host later { hardware ethernet aa:bb:cc:dd:ee:09; fixed-address 192.0.2.15; }\n"
        )
        return result

    monkeypatch.setattr(dhcp, "_configuration_snapshot", snapshot)
    preview = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True})
    assert preview.status_code == 200
    assert state.managed.read_bytes() == b""


def test_candidate_exclusion_uses_snapshot_bytes_and_rejects_native_edit(state, monkeypatch):
    preview = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"preview": True}
    ).json
    capture = dhcp._configuration_snapshot
    candidates = {}
    install = dhcp._install_changes

    def snapshot(*args):
        result = capture(*args)
        state.main.write_text(state.main.read_text().replace("192.0.2.20", "192.0.2.30"))
        return result

    def observe(changes, *args):
        candidates.update(changes)
        return install(changes, *args)

    monkeypatch.setattr(dhcp, "_configuration_snapshot", snapshot)
    monkeypatch.setattr(dhcp, "_install_changes", observe)
    response = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": preview["token"],
            "exclude_from_pools": True,
        },
    )
    assert response.status_code == 409
    assert "range 192.0.2.16 192.0.2.20;" in candidates[state.main]
    assert "range 192.0.2.16 192.0.2.30;" not in candidates[state.main]
    assert state.managed.read_bytes() == b""
    assert "192.0.2.30" in state.main.read_text()


def test_unwritten_config_change_blocks_out_of_pool_reservation(state, monkeypatch):
    capture = dhcp._configuration_snapshot

    def snapshot(*args):
        result = capture(*args)
        state.main.write_text(state.main.read_text().replace("192.0.2.10", "192.0.2.6"))
        return result

    monkeypatch.setattr(dhcp, "_configuration_snapshot", snapshot)
    response = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"address": "192.0.2.6"}
    )
    assert response.status_code == 409
    assert "Configuration changed" in response.json["error"]
    assert state.managed.read_bytes() == b""
    assert "range 192.0.2.6 192.0.2.20" in state.main.read_text()


@pytest.mark.parametrize("phase", ["before-staging", "after-staging"])
def test_transaction_checks_unwritten_read_set(tmp_path, monkeypatch, phase):
    written = tmp_path / "managed"
    observed = tmp_path / "include"
    written.write_bytes(b"original")
    observed.write_bytes(b"observed")
    expected = {written: b"original", observed: b"observed"}
    if phase == "before-staging":
        observed.write_bytes(b"native edit")
    else:
        monkeypatch.setattr(
            "netadmin.agents.common.os.fsync", lambda _fd: observed.write_bytes(b"native edit")
        )
    with pytest.raises(ConfigurationChanged):
        validated_transaction(
            {written: "candidate"},
            lambda: pytest.fail("No validation"),
            [],
            allowed_roots=(tmp_path,),
            expected_originals=expected,
        )
    assert written.read_bytes() == b"original"
    assert observed.read_bytes() == b"native edit"
    assert sorted(tmp_path.iterdir()) == sorted([written, observed])


def test_lease_acquired_during_reload_rolls_back_and_reloads_originals(state, monkeypatch):
    preview = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"preview": True}
    ).json
    original = state.main.read_bytes()
    state.client.application.config["DHCP_RELOAD"] = ["synthetic-reload"]
    reloads = []

    def run(command, **_kwargs):
        if command == ["synthetic-reload"]:
            reloads.append(state.main.read_bytes())
            if len(reloads) == 1:
                state.leases.write_text(lease("aa:bb:cc:dd:ee:09"))

    monkeypatch.setattr(dhcp.subprocess, "run", run)
    response = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": preview["token"],
            "exclude_from_pools": True,
        },
    )
    assert response.status_code == 409
    assert "rolled back" in response.json["error"]
    assert state.main.read_bytes() == original
    assert state.managed.read_bytes() == b""
    assert len(reloads) == 2 and reloads[-1] == original
    assert state.leases.read_text() == lease("aa:bb:cc:dd:ee:09")


def test_post_reload_own_lease_is_allowed(state, monkeypatch):
    preview = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"preview": True}
    ).json
    state.client.application.config["DHCP_RELOAD"] = ["synthetic-reload"]

    def run(command, **_kwargs):
        if command == ["synthetic-reload"]:
            state.leases.write_text(lease(PAYLOAD["mac"]))

    monkeypatch.setattr(dhcp.subprocess, "run", run)
    response = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": preview["token"],
            "exclude_from_pools": True,
        },
    )
    assert response.status_code == 200


@pytest.mark.parametrize("ranges", [[], [["192.0.2.30", "192.0.2.40"]]])
def test_singleton_pool_is_removed_when_edited(ranges):
    text = "subnet 192.0.2.0 netmask 255.255.255.0 {\n range 192.0.2.15;\n}"
    updated = dhcp_files.update_subnet(text, "192.0.2.0", ranges, {})
    assert "range 192.0.2.15;" not in updated
    assert dhcp_files.subnets(updated)[0]["ranges"] == ranges


def test_singleton_pool_is_removed_by_agent_endpoint(state):
    state.main.write_text(
        state.main.read_text().replace("range 192.0.2.10 192.0.2.20;", "\n range 192.0.2.15;\n")
    )
    response = state.client.post(
        "/configuration",
        headers=AUTH,
        json={
            "network": "192.0.2.0",
            "ranges": [],
            "options": {},
        },
    )
    assert response.status_code == 200
    assert dhcp_files.subnets(state.main.read_text())[0]["ranges"] == []


def test_new_managed_file_remains_part_of_snapshot(state):
    state.managed.unlink()
    captured = dhcp._configuration_snapshot(state.main, state.managed)
    assert captured[state.managed] is None
    response = state.client.post(
        "/reservations", headers=AUTH, json=PAYLOAD | {"address": "192.0.2.6"}
    )
    assert response.status_code == 200
    assert "host reviewed" in state.managed.read_text()


def test_transaction_refuses_uncovered_write(tmp_path):
    target = tmp_path / "managed"
    with pytest.raises(ConfigurationChanged, match="Write set"):
        validated_transaction(
            {target: "candidate"},
            lambda: None,
            [],
            allowed_roots=(tmp_path,),
            expected_originals={},
        )
    assert not target.exists()


@pytest.mark.parametrize("keyword", ["RANGE", "RaNgE"])
def test_mixed_case_range_requires_approval_and_is_excluded(state, keyword):
    state.main.write_text(
        state.main.read_text()
        .replace("subnet", "SUBNET")
        .replace("netmask", "NETMASK")
        .replace("range 192.0.2.10", f"{keyword} 192.0.2.10")
    )
    assert f'include "{state.managed}";' in state.main.read_text()
    assert state.client.post("/reservations", headers=AUTH, json=PAYLOAD).status_code == 409
    plan = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True}).json
    assert plan["pool_change"] is True
    response = state.client.post(
        "/reservations",
        headers=AUTH,
        json=PAYLOAD
        | {
            "preview_token": plan["token"],
            "exclude_from_pools": True,
        },
    )
    assert response.status_code == 200
    assert dhcp_files.subnets(state.main.read_text())[0]["ranges"] == plan["after"]


def test_uppercase_singleton_is_removed_and_unsupported_range_is_rejected():
    text = "SUBNET 192.0.2.0 NETMASK 255.255.255.0 {\n RANGE 192.0.2.15;\n}"
    assert (
        dhcp_files.subnets(dhcp_files.update_subnet(text, "192.0.2.0", [], {}))[0]["ranges"] == []
    )
    unsupported = text.replace("RANGE 192.0.2.15;", "RANGE dynamic-bootp 192.0.2.15;")
    assert dhcp_files.subnets(unsupported)[0]["pool_review_supported"] is False
    with pytest.raises(ValueError, match="Unsupported"):
        dhcp_files.exclude_address(unsupported, "192.0.2.0", "192.0.2.15")


@pytest.mark.parametrize("keyword", ["include", "INCLUDE"])
def test_subnet_local_include_rejects_reservation_and_pool_edit(state, keyword):
    included = state.main.parent / "pool.conf"
    included.write_text("range 192.0.2.10 192.0.2.20;\n")
    state.main.write_text(
        state.main.read_text().replace("range 192.0.2.10 192.0.2.20;", f'{keyword} "{included}";')
    )
    original = state.main.read_bytes()
    response = state.client.post("/reservations", headers=AUTH, json=PAYLOAD | {"preview": True})
    assert response.status_code == 409
    assert "natively" in response.json["error"]
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
    assert state.main.read_bytes() == original
    assert state.managed.read_bytes() == b""


def test_include_words_in_comments_and_strings_do_not_disable_review():
    text = (
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n"
        ' # INCLUDE "comment.conf";\n option domain-name "include";\n'
        " range 192.0.2.10 192.0.2.20;\n}"
    )
    assert dhcp_files.subnets(text)[0].get("pool_review_supported", True)
    assert dhcp_files.include_names(text) == []
