"""Administrator-only service logs, separate from NetAdmin activity."""

from __future__ import annotations

from typing import Any, cast

import httpx
from flask import Blueprint, abort, render_template

from netadmin.auth import admin_required, extension
from netadmin.config import Settings
from netadmin.services.agents import AgentClient
from netadmin.services.dns import AgentDnsService

logs_web = Blueprint("service_logs", __name__)
PAGES = {
    "radius-logins": (
        "RADIUS Login Log",
        "radius",
        "logins",
        ("when", "user", "client", "device", "result"),
    ),
    "dhcp-leases": (
        "DHCP Lease Log",
        "dhcp",
        "leases",
        ("when", "action", "address", "device", "hostname", "client"),
    ),
    "ddns-changes": (
        "DDNS Change Log",
        "dns",
        "ddns",
        ("when", "zone", "action", "name", "type", "value", "client"),
    ),
    "radius-sessions": (
        "RADIUS Sessions",
        "radius",
        "sessions",
        (
            "user",
            "status",
            "device",
            "address",
            "client",
            "access_point",
            "started",
            "ended",
            "updated",
            "duration",
            "received",
            "sent",
            "session",
        ),
    ),
}
LABELS = {
    "when": "Time (source timezone)",
    "user": "User",
    "device": "Device MAC",
    "address": "IP address",
    "client": "Client / NAS",
    "access_point": "Access point",
    "started": "Started (UTC)",
    "ended": "Ended (UTC)",
    "updated": "Last update (UTC)",
    "duration": "Duration (seconds)",
    "received": "NAS received (bytes)",
    "sent": "NAS sent (bytes)",
    "session": "Session ID",
}


def _load(service: str, resource: str) -> dict[str, Any]:
    settings = cast(Settings, extension("netadmin_settings"))
    if not settings.service_enabled(service):
        return {"status": "unavailable", "rows": [], "reason": "Service is disabled."}
    agent: AgentClient
    if service == "dns":
        dns = extension("netadmin_dns")
        if not isinstance(dns, AgentDnsService):
            return {
                "status": "unavailable",
                "rows": [],
                "reason": "DDNS logs require a DNS agent connection.",
            }
        agent = dns.client
    else:
        agent = cast(AgentClient, extension(f"netadmin_{service}"))
    try:
        payload = agent.get(f"logs/{resource}")
        if (
            not isinstance(payload, dict)
            or payload.get("status") not in {"available", "unavailable"}
            or not isinstance(payload.get("rows"), list)
            or any(not isinstance(row, dict) for row in payload["rows"])
        ):
            raise ValueError("Invalid log response")
        return {
            "status": payload["status"],
            "rows": payload["rows"][:500] if payload["status"] == "available" else [],
            "reason": str(payload.get("reason", "")),
        }
    except (httpx.HTTPError, OSError, ValueError, TypeError):
        return {
            "status": "unavailable",
            "rows": [],
            "reason": (
                "Logs are unavailable. Check the agent connection, version and log configuration."
            ),
        }


@logs_web.get("/logs/<page>")
@admin_required
def index(page: str) -> Any:
    """Render a bounded native-service log with the shared searchable table controls."""
    if page not in PAGES:
        abort(404)
    title, service, resource, columns = PAGES[page]
    return render_template(
        "service_logs.html",
        title=title,
        page=page,
        columns=columns,
        labels=LABELS,
        sessions=resource == "sessions",
        **_load(service, resource),
    )
