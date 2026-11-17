"""Tests for recursive ISC DHCPD configuration management."""

from pathlib import Path

from netadmin.services.dhcp_files import (
    discover_files,
    global_options,
    kea_export,
    remove_reservation,
    reservations,
    subnets,
    update_subnet,
)


def test_recursive_discovery(tmp_path: Path) -> None:
    child = tmp_path / "child.conf"
    child.write_text("# child")
    main = tmp_path / "dhcpd.conf"
    main.write_text(f'include "{child}";')
    assert discover_files(main) == [main.resolve(), child.resolve()]


def test_reservation_source_and_removal() -> None:
    text = "host pi { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 192.0.2.3; }\n# keep\n"
    assert reservations(text, "legacy.conf")[0]["source"] == "legacy.conf"
    result = remove_reservation(text, "pi")
    assert "host pi" not in result
    assert "# keep" in result


def test_subnet_update_and_kea_export() -> None:
    text = """subnet 192.0.2.0 netmask 255.255.255.0 {
  range 192.0.2.10 192.0.2.20;
  option routers 192.0.2.1;
}"""
    updated = update_subnet(
        text,
        "192.0.2.0",
        [["192.0.2.30", "192.0.2.40"]],
        {"routers": "192.0.2.254"},
    )
    parsed = subnets(updated)
    assert parsed[0]["ranges"] == [["192.0.2.30", "192.0.2.40"]]
    snapshot = kea_export(
        parsed,
        [{"name": "pi", "mac": "aa:bb:cc:dd:ee:ff", "address": "192.0.2.5"}],
    )
    assert snapshot["Dhcp4"]["subnet4"][0]["subnet"] == "192.0.2.0/24"
    assert snapshot["Dhcp4"]["subnet4"][0]["reservations"][0]["hostname"] == "pi"


def test_subnet_update_consumes_preceding_blank_lines() -> None:
    text = """subnet 192.0.2.0 netmask 255.255.255.0 {
  next-server 192.0.2.2;

  range 192.0.2.10 192.0.2.20;
  option routers 192.0.2.1;
}"""
    updated = update_subnet(
        text,
        "192.0.2.0",
        [["192.0.2.30", "192.0.2.40"]],
        {"routers": "192.0.2.254"},
    )
    assert (
        updated
        == """subnet 192.0.2.0 netmask 255.255.255.0 {
  range 192.0.2.30 192.0.2.40;
  option routers 192.0.2.254;
  next-server 192.0.2.2;
}"""
    )


def test_kea_export_places_hosts_by_subnet() -> None:
    items = [
        {
            "network": "192.0.2.0",
            "netmask": "255.255.255.0",
            "ranges": [["192.0.2.10", "192.0.2.20"]],
            "options": {},
        },
        {
            "network": "198.51.100.0",
            "netmask": "255.255.255.0",
            "ranges": [["198.51.100.10", "198.51.100.20"]],
            "options": {},
        },
    ]
    hosts = [
        {"name": "pi", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.5"},
        {"name": "printer", "mac": "aa:bb:cc:dd:ee:02", "address": "198.51.100.5"},
        {"name": "orphan", "mac": "aa:bb:cc:dd:ee:03", "address": "203.0.113.9"},
    ]
    snapshot = kea_export(items, hosts)
    subnets_out = snapshot["Dhcp4"]["subnet4"]
    assert [entry["id"] for entry in subnets_out] == [1, 2]
    assert [host["hostname"] for host in subnets_out[0]["reservations"]] == ["pi"]
    assert [host["hostname"] for host in subnets_out[1]["reservations"]] == ["printer"]
    assert snapshot["Dhcp4"]["reservations-global"] is True
    assert [host["hostname"] for host in snapshot["Dhcp4"]["reservations"]] == ["orphan"]


def test_subnet_in_shared_network_with_subnet_local_pool_stays_supported() -> None:
    # A pool declared inside a nested subnet must not mark the shared network
    # as pool-scoped; the subnet stays reviewable (no false positive).
    text = """shared-network office {
  subnet 192.0.2.0 netmask 255.255.255.0 {
    pool {
      range 192.0.2.10 192.0.2.20;
    }
  }
}"""
    entries = subnets(text)
    assert len(entries) == 1
    assert entries[0].get("pool_review_supported") is None


def test_subnet_in_shared_network_with_direct_range_unsupported() -> None:
    # A bare range declared directly in the shared network scopes every subnet.
    text = """shared-network office {
  range 10.0.0.1 10.0.0.2;
  subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.10 192.0.2.20;
  }
}"""
    entries = subnets(text)
    assert len(entries) == 1
    assert entries[0].get("pool_review_supported") is False


def test_subnet_in_shared_network_with_direct_pool_block_unsupported() -> None:
    # A pool block declared directly in the shared network scopes every subnet.
    text = """shared-network office {
  pool {
    range 10.0.0.1 10.0.0.2;
  }
  subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.10 192.0.2.20;
  }
}"""
    entries = subnets(text)
    assert len(entries) == 1
    assert entries[0].get("pool_review_supported") is False


def test_shared_network_with_both_direct_and_subnet_pool_unsupported() -> None:
    text = """shared-network office {
  pool {
    range 10.0.0.1 10.0.0.2;
  }
  subnet 192.0.2.0 netmask 255.255.255.0 {
    pool {
      range 192.0.2.10 192.0.2.20;
    }
  }
}"""
    entries = subnets(text)
    assert len(entries) == 1
    assert entries[0].get("pool_review_supported") is False


def test_global_options_ignore_subnet_and_host_blocks() -> None:
    text = (
        'option domain-name "lan.example";\n'
        "option domain-name-servers 192.0.2.1, 192.0.2.2;\n"
        "subnet 192.0.2.0 netmask 255.255.255.0 {\n"
        "  option routers 192.0.2.1;\n"
        "  range 192.0.2.10 192.0.2.20;\n"
        "}\n"
        "host pi { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 192.0.2.3; }\n"
    )
    assert global_options(text) == {
        "domain-name": "lan.example",
        "domain-name-servers": "192.0.2.1, 192.0.2.2",
    }
    assert global_options("host pi { option routers 192.0.2.1; }") == {}
