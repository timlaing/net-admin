"""Tests for DHCP parsing and rendering in both backend flavors."""

import pytest

from netadmin.agents.dhcp import parse_leases, parse_reservations, render_reservations


def test_reservation_round_trip() -> None:
    items = [{"name": "pi", "mac": "aa:bb:cc:dd:ee:ff", "address": "192.0.2.20"}]
    assert parse_reservations(render_reservations(items)) == items


def test_parse_leases() -> None:
    text = """lease 192.0.2.10 {
      ends 3 2026/08/26 12:00:00;
      binding state active;
      hardware ethernet aa:bb:cc:dd:ee:ff;
      client-hostname "laptop";
    }"""
    assert parse_leases(text) == [
        {
            "address": "192.0.2.10",
            "state": "active",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "laptop",
            "ends": "3 2026/08/26 12:00:00",
        }
    ]


def test_kea_reservation_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DHCP_SERVER", "kea")
    items = [{"name": "pi", "mac": "aa:bb:cc:dd:ee:ff", "address": "192.0.2.20"}]
    rendered = render_reservations(items)
    assert rendered.startswith("# Managed by NetAdmin.")
    assert '"reservations"' in rendered
    assert parse_reservations(rendered) == items


def test_kea_parse_leases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DHCP_SERVER", "kea")
    text = "192.0.2.10,aa:bb:cc:dd:ee:ff,,3600,1766798400,1,0,0,laptop,0,,\n"
    assert parse_leases(text) == [
        {
            "address": "192.0.2.10",
            "state": "active",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "laptop",
            "ends": "1766798400",
        }
    ]


@pytest.mark.parametrize(
    "pools", [[], [["192.0.2.10", "192.0.2.20"], ["192.0.2.30", "192.0.2.40"]]]
)
def test_pool_addition_and_removal(pools):
    from netadmin.agents.dhcp import _validate_pools

    _validate_pools("192.0.2.0/24", pools)


@pytest.mark.parametrize(
    "pools",
    [
        [["192.0.2.20", "192.0.2.10"]],
        [["198.51.100.10", "198.51.100.20"]],
        [["192.0.2.0", "192.0.2.20"]],
        [["192.0.2.10", "192.0.2.20"], ["192.0.2.20", "192.0.2.30"]],
    ],
)
def test_invalid_pools_rejected(pools):
    from netadmin.agents.dhcp import _validate_pools

    with pytest.raises(ValueError):
        _validate_pools("192.0.2.0/24", pools)
