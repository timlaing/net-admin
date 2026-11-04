"""Restart the installer-owned ISC daemon and wait for its acknowledgement."""

import os
import secrets
import signal
import time
from pathlib import Path


def main():
    """A failed restart must reach the agent's transactional rollback."""
    directory = Path("/run/netadmin")
    nonce = secrets.token_hex(16)
    temporary = directory / "request.tmp"
    temporary.write_text(nonce)
    temporary.replace(directory / "request")
    os.kill(1, signal.SIGHUP)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = directory / "result"
        if result.exists():
            answer = result.read_text().split()
            if answer and answer[0] == nonce:
                if answer != [nonce, "ok"]:
                    raise SystemExit("ISC DHCP failed to start")
                return
        time.sleep(0.1)
    raise SystemExit("ISC DHCP restart acknowledgement timed out")


if __name__ == "__main__":
    main()
