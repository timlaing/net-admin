"""Bounded, read-only readiness checks and container probes; never reload services."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import subprocess  # nosec B404
from pathlib import Path

import httpx

PORTS = {"dhcp": 8081, "radius": 8082, "dns": 8083, "ca": 8084}


def version() -> str:
    """Report only validated build metadata, not arbitrary environment content."""
    value = os.getenv("NETADMIN_BUILD_VERSION", "unknown")
    return value if re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", value) else "unknown"


def _ca_ready(kind: str) -> bool:
    control = os.getenv("CA_CONTROL_SOCKET", "/control/ca.sock" if kind == "runtime" else "")
    if control:
        token = Path(os.environ["CA_MANAGEMENT_TOKEN_FILE"]).read_text(encoding="utf-8").strip()
        with httpx.Client(transport=httpx.HTTPTransport(uds=control), timeout=3) as client:
            response = client.get(
                "http://controller/ready", headers={"X-CA-Management-Token": token}
            )
            body = response.json() if response.status_code == 200 else None
            return isinstance(body, dict) and body.get("ready") is True
    return (
        Path(os.getenv("STEP_CA_ROOT", "/trust/root_ca.crt")).is_file()
        and Path(os.getenv("CA_DATA_DIR", "/data")).is_dir()
    )


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
            return _ca_ready(kind)
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
    if args.port is not None and args.port != PORTS.get(args.kind):
        parser.error("Probe port must match the selected component")
    healthy = ready(args.kind)
    if healthy and args.port:
        try:
            address = ipaddress.ip_address(os.getenv("AGENT_BIND_ADDRESS", "127.0.0.1"))
            host = "127.0.0.1" if address.is_unspecified else str(address)
            with socket.create_connection((host, PORTS[args.kind]), timeout=3) as connection:
                healthy = connection.fileno() >= 0
        except (OSError, ValueError):
            healthy = False
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
