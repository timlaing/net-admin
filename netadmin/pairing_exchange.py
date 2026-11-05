"""Explicit, short-lived host enrollment; no transport authority keys leave the host."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LIMIT = 65_536
PORTS = {"dns": 8083, "dhcp": 8081, "radius": 8082, "ca": 8084}


def parse_code(code: str) -> tuple[str, int, str, str]:
    """Accept literal host addresses and a complete token/fingerprint, never redirects."""
    parsed = urlsplit(code.strip())
    address = ipaddress.IPv4Address(parsed.hostname or "")
    token = parsed.path.removeprefix("/")
    fingerprint = parsed.fragment
    if parsed.scheme != "netadmin-pair" or parsed.username or parsed.password or parsed.query:
        raise ValueError("Invalid pairing code")
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("Invalid pairing address")
    if (
        len(token) != 43
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for c in token
        )
        or len(fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in fingerprint)
    ):
        raise ValueError("Invalid pairing code")
    if not parsed.port or not 1024 <= parsed.port <= 65535:
        raise ValueError("Invalid pairing port")
    return str(address), parsed.port, token, fingerprint


def claim(code: str) -> dict[str, Any]:
    """Pin TLS before transmitting the single-use secret; bound time and response size."""
    host, port, token, fingerprint = parse_code(code)
    # Retrieve public identity only, then authenticate it using the out-of-band pin.
    certificate = ssl.get_server_certificate((host, port), timeout=10)
    actual = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    if not hmac.compare_digest(actual, fingerprint):
        raise ValueError("Pairing host identity does not match")
    context = ssl.create_default_context(cadata=certificate)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Trust only this pinned leaf while retaining SAN, validity and usage checks.
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # pylint: disable=no-member
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=10)
    try:
        connection.request(
            "POST", "/claim", headers={"Authorization": f"Bearer {token}", "Content-Length": "0"}
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Pairing code expired or already used")
        content = response.read(LIMIT + 1)
        if len(content) > LIMIT:
            raise ValueError("Pairing response exceeds limit")
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("Invalid pairing response")
        payload["address"] = host
        return payload
    finally:
        connection.close()


def serve(directory: Path, port: int = 8085, lifetime: int = 600) -> None:
    """Serve one authenticated claim, then close; restart explicitly to issue another code."""
    state = json.loads((directory / "installation.json").read_text())
    if state.get("schema") != 1 or state.get("project") != "netadmin-services":
        raise ValueError("Unrecognized installation")
    address = str(ipaddress.IPv4Address(state["address"]))
    selected = [name for name in PORTS if state[name] not in {"no", "none"}]
    if not selected:
        raise ValueError("No installed agents")
    identity = directory / "transport" / selected[0]
    cert = identity / "server.crt"
    token = secrets.token_urlsafe(32)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    agents = {
        line.partition("=")[0]: line.partition("=")[2]
        for line in (directory / "agents.env").read_text().splitlines()
        if "=" in line
    }
    payload = {
        "schema": 1,
        "services": selected,
        "token": agents["NETADMIN_AGENT_TOKEN"],
        "ca": (directory / "transport/client/ca.crt").read_text(),
        "certificate": (directory / "transport/client/client.crt").read_text(),
        "key": (directory / "transport/client/client.key").read_text(),
        "management_token": (directory / "secrets/management-token").read_text().strip()
        if "ca" in selected
        else "",
    }
    deadline = time.monotonic() + lifetime
    consumed = False

    class Handler(BaseHTTPRequestHandler):
        """Reject every request except an authenticated, unexpired, single claim."""

        def setup(self) -> None:
            """Keep slow clients from extending the bounded enrollment window."""
            self.request.settimeout(5)
            super().setup()

        def log_message(self, format: str, *args: Any) -> None:
            """Never log tokens or credential payloads."""

        def do_POST(self) -> None:  # pylint: disable=invalid-name
            """Consume authorization before transmitting any credentials."""
            nonlocal consumed
            if (
                self.path != "/claim"
                or consumed
                or time.monotonic() >= deadline
                or not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}")
            ):
                self.send_error(403)
                return
            consumed = True
            content = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, identity / "server.key")
    with HTTPServer((address, port), Handler) as server:
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False
        )
        server.timeout = 1
        print(
            f"Pairing expires in {lifetime // 60} minutes. "
            "Paste into NetAdmin Settings > Pair installation:",
            flush=True,
        )
        print(f"netadmin-pair://{address}:{server.server_port}/{token}#{fingerprint}", flush=True)
        while not consumed and time.monotonic() < deadline:
            try:
                server.handle_request()
            except (TimeoutError, OSError):
                continue
    print("Pairing closed. Run this command again if enrollment did not finish.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8085)
    arguments = parser.parse_args()
    serve(arguments.directory, arguments.port)
