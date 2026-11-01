"""HTTP clients for the privileged sidecar agents."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx


class AgentClient:
    """Authenticated JSON client for a local service agent."""

    def __init__(
        self,
        base_url: str,
        token: str,
        ca: Path | None = None,
        cert: Path | None = None,
        key: Path | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.ca = ca
        self.cert = cert
        self.key = key

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca) if self.ca else None)
        if self.cert and self.key:
            context.load_cert_chain(str(self.cert), str(self.key))
        return context

    def get(self, path: str, *, timeout: float = 10) -> Any:
        """Fetch JSON from the agent."""
        with httpx.Client(verify=self._tls_context()) as client:
            response = client.get(
                f"{self.base_url}/{path.lstrip('/')}", headers=self.headers, timeout=timeout
            )
        response.raise_for_status()
        return response.json()

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        """Post JSON to the agent."""
        with httpx.Client(verify=self._tls_context()) as client:
            response = client.post(
                f"{self.base_url}/{path.lstrip('/')}",
                headers=self.headers,
                json=payload,
                timeout=20,
            )
        response.raise_for_status()
        return response.json()

    def read_only(self) -> bool:
        """Recognize older agents without disabling their existing write API."""
        try:
            capabilities = self.get("capabilities")
            return isinstance(capabilities, dict) and bool(capabilities.get("read_only", False))
        except httpx.HTTPStatusError as error:
            if error.response.status_code != 404:
                raise
            return False
