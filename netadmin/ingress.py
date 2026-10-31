"""Home Assistant ingress URL and cookie handling."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from typing import Any

from flask import Flask, request
from flask.sessions import SecureCookieSessionInterface
from werkzeug.wrappers import Response

_PREFIX = re.compile(r"/api/(?:hassio_ingress|hassio/ingress)/[A-Za-z0-9_-]+")
# Home Assistant requires this fixed Supervisor peer for ingress authentication.
# https://developers.home-assistant.io/docs/apps/presentation/
# This is a trust boundary, not a configurable outbound service address.
SUPERVISOR_INGRESS_ADDRESS = "172.30.32.2"  # NOSONAR - required, reviewed ingress peer allowlist.


def supports_ingress_identity() -> bool:
    """Older Supervisor releases do not sanitize the groups header reliably."""
    version = re.fullmatch(
        r"(\d{4})\.(\d{1,2})\.(\d+)", os.getenv("NETADMIN_SUPERVISOR_VERSION", "")
    )
    return bool(version and tuple(map(int, version.groups())) >= (2026, 10, 5))


class IngressSessionInterface(SecureCookieSessionInterface):
    """Keep the CSRF session cookie within the app's ingress path."""

    def get_cookie_path(self, app: Flask) -> str:
        return request.script_root or super().get_cookie_path(app)


def configure_ingress(app: Flask) -> None:
    """Install only on the ingress-only Home Assistant app, never standalone.

    Supervisor strips the prefix before forwarding PATH_INFO and supplies it
    in X-Ingress-Path. SCRIPT_NAME restores Flask's URL generation. Only trust
    the forwarded scheme when that ingress routing header is also present.
    """
    original = app.wsgi_app

    def ingress(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        """Restore the externally visible mount point before Flask routes."""
        prefix = environ.get("HTTP_X_INGRESS_PATH", "")
        if prefix:
            if environ.get("REMOTE_ADDR") != SUPERVISOR_INGRESS_ADDRESS:
                return Response("Ingress requests must come from Supervisor", status=403)(
                    environ, start_response
                )
            if not _PREFIX.fullmatch(prefix):
                return Response("Invalid ingress path", status=400)(environ, start_response)
            environ["SCRIPT_NAME"] = prefix
            environ["netadmin.trusted_ingress"] = True
            scheme = environ.get("HTTP_X_FORWARDED_PROTO", "")
            if scheme in {"http", "https"}:
                environ["wsgi.url_scheme"] = scheme
        return original(environ, start_response)

    app.wsgi_app = ingress  # type: ignore[method-assign]  # Flask's documented middleware hook.
    app.session_interface = IngressSessionInterface()
