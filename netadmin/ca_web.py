"""Administrative CSR issuance and revocation through the restricted CA agent."""

from __future__ import annotations

import uuid
from typing import Any, cast
from urllib.parse import urlencode

import httpx
from cryptography import x509
from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for

from netadmin.auth import admin_required, current_identity, extension
from netadmin.config import Settings
from netadmin.services.agents import AgentClient
from netadmin.services.step_ca import validate_csr
from netadmin.store import Store

ca_web = Blueprint("ca", __name__)


CA_TEMPLATE = "ca.html"
CA_INDEX = "ca.index"


def _client() -> AgentClient:
    settings = cast(Settings, extension("netadmin_settings"))
    if not settings.ca_agent_url:
        abort(404)
    return AgentClient(
        settings.ca_agent_url,
        settings.agent_token,
        settings.agent_ca,
        settings.agent_cert,
        settings.agent_key,
    )


def _audit(action: str, success: bool | None) -> None:
    cast(Store, extension("netadmin_store")).audit(
        current_identity().username, f"ca.{action}", "Certificates", success
    )


def _unknown_outcome(action: str) -> Any:
    _audit(action, None)
    flash("CA operation outcome is unknown. Inspect the inventory before retrying.", "warning")
    return redirect(url_for(CA_INDEX))


@ca_web.get("/certificates")
@admin_required
def index() -> Any:
    """List the agent's public issuance inventory."""
    return _render_inventory(_client(), request_id=uuid.uuid4().hex)


def _render_inventory(client: AgentClient, **context: Any) -> Any:
    try:
        cursor = request.args.get("after", "")
        inventory = client.get(
            "certificates" + ("?" + urlencode({"after": cursor}) if cursor else "")
        )
        read_only = client.read_only()
    except httpx.HTTPError:
        return render_template(CA_TEMPLATE, unavailable=True, certificates=[], read_only=True), 502
    return render_template(
        CA_TEMPLATE,
        certificates=inventory["certificates"],
        read_only=read_only,
        next_cursor=inventory.get("next_cursor"),
        **context,
    )


@ca_web.post("/certificates/inspect")
@admin_required
def inspect() -> Any:
    """Decode a CSR for human approval without issuing a certificate."""
    client = _client()
    pem = request.form.get("csr", "")
    try:
        csr = validate_csr(pem)
        try:
            names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans = ", ".join(str(name.value) for name in names)
        except x509.ExtensionNotFound:
            sans = "No SANs requested"
        preview = {
            "subject": csr.subject.rfc4514_string(),
            "sans": sans,
            "key_bits": getattr(csr.public_key(), "key_size", 0),
        }
    except (ValueError, TypeError):
        flash(
            "Invalid CSR: check its signature, public key strength and requested usages.", "danger"
        )
        return redirect(url_for(CA_INDEX))
    return _render_inventory(
        client,
        csr=pem,
        preview=preview,
        days=request.form.get("days", "365"),
        request_id=request.form.get("request_id") or uuid.uuid4().hex,
    )


@ca_web.post("/certificates")
@admin_required
def issue() -> Any:
    """Approve a CSR and download its signed certificate chain."""
    client = _client()
    if client.read_only():
        abort(403)
    if request.form.get("confirm") != "yes":
        abort(400)
    try:
        result = client.post(
            "certificates",
            {
                "csr": request.form.get("csr", ""),
                "days": request.form.get("days", "365"),
                **(
                    {"request_id": request.form["request_id"]}
                    if request.form.get("request_id")
                    else {}
                ),
            },
            timeout=60,
        )
    except httpx.TimeoutException:
        return _unknown_outcome("issue")
    except httpx.HTTPError:
        _audit("issue", False)
        raise
    _audit("issue", True)
    flash("Certificate issued. Download its chain from the inventory.", "success")
    return redirect(url_for(CA_INDEX, issued=result["id"]))


@ca_web.post("/certificates/<identifier>/revoke")
@admin_required
def revoke(identifier: str) -> Any:
    """Record irreversible revocation at the authority."""
    client = _client()
    if client.read_only():
        abort(403)
    if request.form.get("confirm") != "yes":
        abort(400)
    try:
        client.post(
            f"certificates/{identifier}/revoke",
            {"reason": request.form.get("reason", "0")},
            timeout=60,
        )
    except httpx.TimeoutException:
        return _unknown_outcome("revoke")
    except httpx.HTTPError:
        _audit("revoke", False)
        raise
    _audit("revoke", True)
    flash(
        "Revocation recorded. Clients must check the CA's CRL to reject it before expiry.",
        "success",
    )
    return redirect(url_for(CA_INDEX))


@ca_web.post("/certificates/revoke-serial")
@admin_required
def revoke_serial() -> Any:
    """Revoke a current serial even when it was issued by direct renewal."""
    client = _client()
    if client.read_only():
        abort(403)
    if request.form.get("confirm") != "yes":
        abort(400)
    try:
        client.post(
            "revoke",
            {"serial": request.form.get("serial", ""), "reason": request.form.get("reason", "0")},
            timeout=60,
        )
    except httpx.TimeoutException:
        return _unknown_outcome("revoke")
    except httpx.HTTPError:
        _audit("revoke", False)
        raise
    _audit("revoke", True)
    flash("Revocation recorded. Automatic renewal of this serial is blocked.", "success")
    return redirect(url_for(CA_INDEX))


@ca_web.get("/certificates/<identifier>/download")
@admin_required
def download(identifier: str) -> Any:
    """Download public certificate chains only."""
    try:
        result = _client().get("crl" if identifier == "crl" else f"certificates/{identifier}")
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            abort(404)
        return render_template(CA_TEMPLATE, unavailable=True, certificates=[], read_only=True), 502
    except httpx.HTTPError:
        return render_template(CA_TEMPLATE, unavailable=True, certificates=[], read_only=True), 502
    return Response(
        result["pem"],
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="certificate-chain.pem"',
            "Cache-Control": "no-store",
        },
    )
