"""Tests for Bind discovery and paired updates."""

from pathlib import Path

import pytest

from netadmin.services.dns import BindService, discover_zones


def test_discover_static_and_dynamic_zones() -> None:
    zones = discover_zones(
        """zone "static.example" { type master; file "fwd/static.zone"; };
zone "dyn.example" { type primary; file "fwd/dyn.zone"; allow-update { key "update"; }; };
zone "forward.example" { type forward; forwarders { 192.0.2.1; }; };"""
    )
    assert [(zone.name, zone.dynamic) for zone in zones] == [
        ("static.example", False),
        ("dyn.example", True),
    ]


def test_zones_from_file(tmp_path: Path) -> None:
    config = tmp_path / "named.conf"
    config.write_text('zone "example" { type master; file "example.zone"; };')
    service = BindService("dns", "key", "", config_path=config)
    assert service.zones()[0].file == "example.zone"


def test_host_update_compensates_on_ptr_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    service = BindService("dns", "key", "")
    calls: list[tuple[str, ...]] = []

    def upsert(*args: str | int) -> None:
        calls.append(tuple(str(value) for value in args))
        if args[2] == "PTR":
            raise RuntimeError("reverse failed")

    monkeypatch.setattr(service, "records", lambda _zone: [])
    monkeypatch.setattr(service, "upsert", upsert)
    monkeypatch.setattr(service, "delete", lambda *args: calls.append(tuple(args)))
    with pytest.raises(RuntimeError):
        service.add_host("pi", "192.168.50.20", "dyn.example", "50.168.192.in-addr.arpa", 300)
    assert calls[-1] == ("dyn.example", "pi", "A", "192.168.50.20")
