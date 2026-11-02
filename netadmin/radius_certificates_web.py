"""Administrative public-certificate views; all private operations run on the agent."""

from __future__ import annotations

from typing import Any, cast

import httpx
from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for

from netadmin.auth import admin_required, current_identity, extension
from netadmin.services.agents import AgentClient
from netadmin.store import Store

certificate_web = Blueprint("radius_certificates", __name__)


def _audit(action: str, success: bool | None) -> None:
    cast(Store, extension("netadmin_store")).audit(
        current_identity().username, f"radius.certificate.{action}", "RADIUS TLS", success
    )


@certificate_web.get("/radius/certificates")
@admin_required
def index() -> Any:
    """Show current public metadata without breaking older agents' RADIUS UI."""
    client = cast(AgentClient, extension("netadmin_radius"))
    try:
        certificates = client.get("certificates")
    except httpx.HTTPError:
        certificates = {
            "available": False,
            "reason": "Certificate details are unavailable. "
            "Update the RADIUS agent and check its connection.",
        }
    return render_template(
        "radius_certificates.html", certificates=certificates, read_only=client.read_only()
    )


@certificate_web.post("/radius/certificates")
@admin_required
def operate() -> Any:
    """Require explicit confirmation and delegate the entire transaction."""
    client = cast(AgentClient, extension("netadmin_radius"))
    if client.read_only():
        abort(403)
    action = request.form.get("action", "")
    if action not in {
        "create-server",
        "enroll-step-ca",
        "renew-server",
        "revoke-server",
        "renew-ca",
        "retire-ca",
        "refresh-crl",
    }:
        abort(400)
    if request.form.get("confirm") != "yes":
        abort(400, "Confirm the effect on RADIUS clients before continuing.")
    try:
        client.post(
            "certificates",
            {
                "action": action,
                "expected_ca": request.form.get("expected_ca", ""),
                "expected_server": request.form.get("expected_server", ""),
                "confirmation": request.form.get("confirmation", ""),
                **{
                    field: request.form[field]
                    for field in ("common_name", "sans", "days")
                    if field in request.form
                },
            },
            timeout=60,
        )
    except httpx.TimeoutException:
        _audit(action, None)
        flash(
            "Certificate operation outcome is unknown. Refresh status before retrying; "
            "the agent may still be applying it.",
            "warning",
        )
        return redirect(url_for("radius_certificates.index"))
    except httpx.HTTPError:
        _audit(action, False)
        raise
    _audit(action, True)
    flash(
        "Certificate change applied and RADIUS restarted. "
        "Existing connections may need to reconnect.",
        "success",
    )
    return redirect(url_for("radius_certificates.index"))


@certificate_web.get("/radius/certificates/download/<kind>")
@admin_required
def download(kind: str) -> Any:
    """Download public certificates or CRLs, never a private key or key bundle."""
    if kind not in {"ca", "server", "crl"}:
        abort(404)
    payload = cast(AgentClient, extension("netadmin_radius")).get(f"certificates/{kind}")
    return Response(
        payload["pem"],
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="radius-{kind}.pem"',
            "Cache-Control": "no-store",
        },
    )
