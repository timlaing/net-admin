"""Parsers reject incomplete or ambiguous native configuration without discarding data."""

import json

import pytest

from netadmin.services import dhcp_files, kea_files, radius_modes, radius_users
from tests.test_radius_modes import EAP, INNER


def test_kea_strings_comments_and_new_subnet_arrays_are_preserved():
    original = {
        "Dhcp4": {
            "subnet4": [
                {"user-context": {}, "id": 1, "subnet": "192.0.2.0/24", "valid-lifetime": 7200}
            ]
        }
    }
    rendered = kea_files.update_subnet(
        json.dumps(original), "192.0.2.0", [["192.0.2.10", "192.0.2.20"]], {"routers": "192.0.2.1"}
    )
    subnet = json.loads(rendered)["Dhcp4"]["subnet4"][0]
    assert subnet["pools"] == [{"pool": "192.0.2.10 - 192.0.2.20"}]
    assert subnet["option-data"] == [{"name": "routers", "data": "192.0.2.1"}]
    assert subnet["valid-lifetime"] == 7200
    assert subnet["user-context"] == {}
    text = (
        '"reservations": [ /* retained comment */ '
        + json.dumps(
            {
                "hostname": 'quoted"{name}',
                "hw-address": "AA:BB:CC:DD:EE:FF",
                "ip-address": "192.0.2.9",
            }
        )
        + "]"
    )
    assert kea_files.parse_reservations(text) == [
        {"name": 'quoted"{name}', "mac": "aa:bb:cc:dd:ee:ff", "address": "192.0.2.9"}
    ]


@pytest.mark.parametrize(
    "text",
    [
        '"reservations": [{"hostname":"unterminated}]',
        '"reservations": [ /* unterminated',
        '"reservations": [{"hostname":"x"}',
    ],
)
def test_kea_unterminated_input_is_rejected(text):
    with pytest.raises(ValueError):
        kea_files.parse_reservations(text)


def test_kea_member_without_enclosing_object_is_rejected_and_missing_includes_are_bounded(tmp_path):
    with pytest.raises(ValueError, match="outside an object"):
        kea_files.update_subnet('"subnet": "192.0.2.0/24"', "192.0.2.0", [], {})
    first = tmp_path / "main.conf"
    second = tmp_path / "second.conf"
    first.write_text('<?include "second.conf"?>\n<?include "missing.conf"?>')
    second.write_text('<?include "main.conf"?>')
    assert kea_files.discover_files(first) == [first, second]


def test_isc_rejects_unbalanced_subnets_and_retains_unmatched_host_entries():
    text = (
        "subnet 192.0.2.0 netmask 255.255.255.0 { range 192.0.2.10 192.0.2.20; }\n"
        "subnet 198.51.100.0 netmask 255.255.255.0 {}\n"
    )
    with pytest.raises(KeyError, match="Unknown subnet"):
        dhcp_files.update_subnet(text, "203.0.113.0", [], {})
    with pytest.raises(ValueError, match="Unbalanced"):
        dhcp_files.update_subnet("subnet 192.0.2.0 netmask 255.255.255.0 {", "192.0.2.0", [], {})
    host = "host retained { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 192.0.2.1; }\n"
    assert dhcp_files.remove_reservation(host, "unknown") == host


@pytest.mark.parametrize(
    "text",
    [
        'alice Crypt-Password := "$6$synthetic" ambiguous\n',
        "alice unsupported check expression\n",
        'alice Crypt-Password := "$6$one", Crypt-Password := "$6$two"\n',
        'alice Cleartext-Password := "synthetic-password"\n',
        'alice Filter-Id := "netadmin-standard"\n',
        'alice Crypt-Password := "$6$one"\nalice Crypt-Password := "$6$two"\n',
        "    unsupported managed directive\n",
    ],
)
def test_managed_radius_records_require_unambiguous_supported_credentials(text):
    with pytest.raises(ValueError):
        radius_users.managed_entries(text)


def test_radius_migration_retains_passwordless_native_policies():
    native = 'policy Filter-Id := "native-policy"\n\tReply-Message := "retained"\n'
    assert radius_users.parse_authorize(native, "native") == []

    def hasher(_password):
        pytest.fail("Passwordless policy must not invoke password hashing")

    remaining, entries = radius_users.migrate_to_managed(native, hasher, set(), "admin", "standard")
    assert remaining == native
    assert entries == {}
    assert radius_users.migrate_authorize(native, hasher, set(), "admin", "standard") == (
        native,
        [],
    )


@pytest.mark.parametrize(
    "text",
    [
        "}",
        "eap {",
        EAP.replace(" default_eap_type = md5", " default_eap_type = md5\n default_eap_type = peap"),
        EAP.replace("default_eap_type = md5", "default_eap_type = !"),
        EAP.replace(" md5 {", " complex method {"),
    ],
)
def test_radius_eap_inventory_rejects_ambiguous_or_complex_configuration(text):
    with pytest.raises(ValueError):
        radius_modes.inventory(text, INNER)


def test_radius_eap_management_requires_standard_inner_and_all_method_templates():
    for eap, inner in (
        (EAP, INNER.replace("inner-tunnel", "other-tunnel")),
        (EAP.replace(" md5 {", " tls {"), INNER),
        (EAP.replace(" tls {", " other_tls {"), INNER),
    ):
        with pytest.raises(ValueError):
            radius_modes.configure(eap, inner, ["peap"], "peap")
    assert (
        radius_modes.inventory(EAP.replace(" default_eap_type = md5\n", ""), INNER)["preferred"]
        == ""
    )
