"""Bounded, read-only readiness checks and container probes; never reload services."""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess  # nosec B404
from pathlib import Path

import httpx


def version() -> str:
    """Report only validated build metadata, not arbitrary environment content."""
    value = os.getenv("NETADMIN_VERSION", "unknown")
    return value if re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", value) else "unknown"


def ready(kind: str) -> bool:
    """Check required configuration or CA controller/issuer readiness without writes."""
    try:
        if kind == "dhcp":
            path = os.getenv("DHCP_MAIN_CONFIG", "/etc/dhcp/dhcpd.conf")
            command = (
                ["/usr/sbin/kea-dhcp4", "-t", path]
                if os.getenv("DHCP_SERVER") == "kea"
                else ["/usr/sbin/dhcpd", "-t", "-4", "-cf", path]
            )
            subprocess.run(command, capture_output=True, check=True, timeout=5)  # noqa: S603
        elif kind == "dns":
            subprocess.run(  # noqa: S603
                ["/usr/bin/named-checkconf", os.getenv("DNS_MAIN_CONFIG", "/etc/bind/named.conf")],
                capture_output=True,
                check=True,
                timeout=5,
            )
        elif kind == "radius":
            paths = (
                ("RADIUS_AUTHORIZE_FILE", "/etc/raddb/mods-config/files/authorize"),
                ("RADIUS_CLIENTS_FILE", "/etc/raddb/clients.conf"),
            )
            return all(
                Path(os.getenv(key, default)).is_file()
                and os.access(os.getenv(key, default), os.R_OK)
                for key, default in paths
            )
        elif kind in {"ca", "runtime"}:
            control = os.getenv(
                "CA_CONTROL_SOCKET", "/control/ca.sock" if kind == "runtime" else ""
            )
            if control:
                token = (
                    Path(os.environ["CA_MANAGEMENT_TOKEN_FILE"]).read_text(encoding="utf-8").strip()
                )
                with httpx.Client(transport=httpx.HTTPTransport(uds=control), timeout=3) as client:
                    response = client.get(
                        "http://controller/ready", headers={"X-CA-Management-Token": token}
                    )
                    return response.status_code == 200 and response.json().get("ready") is True
            return (
                Path(os.getenv("STEP_CA_ROOT", "/trust/root_ca.crt")).is_file()
                and Path(os.getenv("CA_DATA_DIR", "/data")).is_dir()
            )
        else:
            return False
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, httpx.HTTPError):
        return False
    return True


def main() -> None:
    """Probe readiness and the running listener without weakening mTLS or mounting keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("dns", "dhcp", "radius", "ca", "runtime"))
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    healthy = ready(args.kind)
    if healthy and args.port:
        host = os.getenv("AGENT_BIND_ADDRESS", "127.0.0.1")
        host = "127.0.0.1" if host == "0.0.0.0" else host  # noqa: S104 - connect only, never bind
        try:
            with socket.create_connection((host, args.port), timeout=3):
                pass
        except OSError:
            healthy = False
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
