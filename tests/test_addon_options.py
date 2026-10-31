"""Upgrade migration from duplicate Supervisor options to in-app settings."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from netadmin.addon_options import LEGACY_CONNECTION_OPTIONS, migrate_connection_options
from netadmin.preferences import read_env_file, write_env_file


def test_import_preserves_saved_values_and_retires_all_legacy_keys(tmp_path, monkeypatch):
    path = tmp_path / "netadmin.env"
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(path))
    write_env_file(
        {
            "NETADMIN_DNS_SERVER": "saved.example",
            "NETADMIN_DNS_ZONES": "",
            "NETADMIN_SECRET_KEY": "keep",
        }
    )
    options = {
        "dns_server": "old.example",
        "dns_zones": "old.example",
        "dhcp_backend": "kea",
        "dhcp_agent_url": "https://dhcp.example:8081",
        "radius_agent_url": "https://radius.example:8082",
        "ingress_require_login": False,
    }
    assert set(migrate_connection_options(options)) == set(LEGACY_CONNECTION_OPTIONS)
    saved = read_env_file()
    assert saved["NETADMIN_DNS_SERVER"] == "saved.example"
    assert saved["NETADMIN_DNS_ZONES"] == ""
    assert saved["NETADMIN_SECRET_KEY"] == "keep"  # noqa: S105 - synthetic sentinel
    assert saved["NETADMIN_DHCP_BACKEND"] == "kea"
    assert saved["NETADMIN_DHCP_AGENT_URL"] == "https://dhcp.example:8081"
    assert saved["NETADMIN_RADIUS_AGENT_URL"] == "https://radius.example:8082"
    assert "NETADMIN_INGRESS_REQUIRE_LOGIN" not in saved
    assert path.stat().st_mode & 0o777 == 0o640
    previous = path.read_bytes()
    migrate_connection_options(options)
    assert path.read_bytes() == previous


def test_new_install_does_not_create_configuration(tmp_path, monkeypatch):
    path = tmp_path / "netadmin.env"
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(path))
    assert migrate_connection_options({"ingress_require_login": True}) == ()
    assert not path.exists()


@pytest.mark.parametrize("invalid", [None, False, ["unexpected"], "host\nINJECTED=1"])
def test_invalid_legacy_values_do_not_overwrite_configuration(tmp_path, monkeypatch, invalid):
    path = tmp_path / "netadmin.env"
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(path))
    write_env_file({"NETADMIN_SECRET_KEY": "keep"})
    previous = path.read_bytes()
    with pytest.raises(ValueError):
        migrate_connection_options({"dhcp_backend": "kea", "dns_server": invalid})
    assert path.read_bytes() == previous


def test_entrypoint_saves_before_removing_options_and_starts_with_imported_values(
    tmp_path, monkeypatch
):
    path = tmp_path / "netadmin.env"
    monkeypatch.setenv("NETADMIN_ENV_FILE", str(path))
    options = {"dhcp_backend": "kea", "dns_server": "legacy.example", "dns_zones": ""}
    monkeypatch.setenv("SYNTHETIC_OPTIONS", json.dumps(options))
    stub = tmp_path / "gunicorn"
    stub.write_text('#!/bin/sh\nprintf "%s|%s" "$NETADMIN_DHCP_BACKEND" "$NETADMIN_DNS_SERVER"\n')
    stub.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tmp_path}:{Path(sys.executable).parent}:/usr/bin:/bin")
    script = Path(__file__).resolve().parents[1] / "home-assistant/netadmin/run.sh"
    shell = """
      function bashio::addon.options() { printf '%s' "$SYNTHETIC_OPTIONS"; }
      function bashio::config() { printf true; }
      function bashio::addon.option() {
        grep -q NETADMIN_DHCP_BACKEND "$NETADMIN_ENV_FILE" || exit 20
        printf '%s\n' "$1" >> "$NETADMIN_ENV_FILE.removed"
      }
      function bashio::info.supervisor() { printf 2026.10.5; }
      source "$1"
    """
    result = subprocess.run(  # noqa: S603 - fixed entrypoint and synthetic Bashio functions
        ["/bin/bash", "-c", shell, "probe", str(script)],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "kea|legacy.example"
    assert set(path.with_suffix(".env.removed").read_text().splitlines()) == set(options)
    assert read_env_file()["NETADMIN_DNS_ZONES"] == ""


def test_addon_exposes_only_ingress_policy():
    root = Path(__file__).resolve().parents[1] / "home-assistant/netadmin"
    config = yaml.safe_load((root / "config.yaml").read_text())
    translations = yaml.safe_load((root / "translations/en.yaml").read_text())
    assert config["options"] == {"ingress_require_login": True}
    assert config["schema"] == {"ingress_require_login": "bool"}
    assert set(translations["configuration"]) == {"ingress_require_login"}
