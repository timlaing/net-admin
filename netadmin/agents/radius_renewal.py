"""Separate supervised renewal worker using the RADIUS agent's activation boundary."""

from __future__ import annotations

import fcntl
import logging
import os
import time
from pathlib import Path

from netadmin.agents.radius import create_radius_agent
from netadmin.agents.radius_certificates import _install, _inventory, _password
from netadmin.agents.radius_step_ca import changes, enabled, managed, renewal_due
from netadmin.services.step_ca import failure_category

LOGGER = logging.getLogger(__name__)


def renew_once() -> bool:
    """Serialize with manual changes and re-read the active identity under the lock."""
    if (
        not enabled()
        or os.getenv("RADIUS_CERT_AUTO_RENEW", "false") != "true"
        or os.getenv("NETADMIN_AGENT_READ_ONLY", "false") == "true"
    ):
        return False
    directory = Path(os.getenv("RADIUS_CERT_DIR", "/etc/raddb/certs"))
    with (directory / ".netadmin-cert-lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        bundle = (directory / "server.pem").read_bytes()
        if not renewal_due(bundle) or not managed(bundle) or not _inventory()["can_manage"]:
            return False
        _install(changes(directory, _password(), {"action": "renew-server"}))
        return True


def main() -> None:
    """Keep running through CA/network outages without exposing secret exceptions."""
    logging.basicConfig(level=logging.INFO)
    app = create_radius_agent()
    while True:
        try:
            with app.app_context():
                if renew_once():
                    LOGGER.info("RADIUS certificate renewed and activated")
        except Exception as error:  # pylint: disable=broad-exception-caught
            # Never log raw subprocess exceptions: command arguments can contain tokens.
            LOGGER.error(  # NOSONAR
                "RADIUS renewal failed; previous identity retained: %s", failure_category(error)
            )
        time.sleep(60)


if __name__ == "__main__":
    main()
