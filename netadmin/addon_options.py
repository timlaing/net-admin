"""One-time import of retired Home Assistant connection options."""

from __future__ import annotations

import json
import sys
from typing import Any

from netadmin.preferences import read_env_file, write_env_file

LEGACY_CONNECTION_OPTIONS = (
    "dhcp_backend",
    "dns_server",
    "dns_zones",
    "dhcp_agent_url",
    "radius_agent_url",
)


def migrate_connection_options(options: dict[str, Any]) -> tuple[str, ...]:
    """Save missing assignments before the entrypoint removes retired options.

    Saved assignments, including empty strings, always win. No credentials or
    ingress policy are imported from Supervisor's options into the env file.
    """
    retired = tuple(name for name in LEGACY_CONNECTION_OPTIONS if name in options)
    if not retired:
        return ()
    saved = read_env_file()
    imported = {}
    for name in retired:
        value = options[name]
        if not isinstance(value, str):
            raise ValueError(f"Legacy {name} must be text")
        key = f"NETADMIN_{name.upper()}"
        if key not in saved:
            imported[key] = value
    if imported:
        write_env_file(imported)
    return retired


def main() -> None:
    """Print only safe retired option names after a successful durable import."""
    options = json.load(sys.stdin)
    if not isinstance(options, dict):
        raise ValueError("Home Assistant options must be a JSON object")
    print(" ".join(migrate_connection_options(options)))


if __name__ == "__main__":
    main()
