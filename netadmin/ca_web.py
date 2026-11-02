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


UNCERTAIN_TRANSPORT_ERRORS = (
    httpx.TimeoutException,
    httpx.ReadError,
    httpx.RemoteProtocolError,
    httpx.WriteError,
)


def _audit(action: str, success: bool | None, details: dict[str, str]) -> None:
    target = next(
        (details[key] for key in ("serial", "certificate_id", "request_id") if details.get(key)),
        "Certificates",
    )
    cast(Store, extension("netadmin_store")).audit(
        current_identity().username, f"ca.{action}", target, success, details
    )


def _request_id(value: str | None = None) -> str:
    value = value or request.form.get("request_id") or uuid.uuid4().hex
    if len(value) != 32 or any(char not in "0123456789abcdef" for char in value):
        abort(400, "Invalid request ID")
    return uuid.UUID(hex=value).hex


def _unknown_outcome(action: str, details: dict[str, str]) -> Any:
    _audit(action, None, details)
    flash("CA operation outcome is unknown. Inspect the inventory before retrying.", "warning")
    if action == "issue":
        # Render the original form rather than creating a new operation on redirect.
        return render_template(
            CA_TEMPLATE,
            certificates=[],
            read_only=False,
            inventory_unavailable=True,
            pending_issue=True,
            request_id=details["request_id"],
            csr=request.form.get("csr", ""),
            days=request.form.get("days", "365"),
        ), 202
    return redirect(url_for(CA_INDEX))


def _reported_unknown(error: httpx.HTTPError) -> bool:
    if not isinstance(error, httpx.HTTPStatusError):
        return False
    if error.response.status_code >= 500:
        return True
    try:
        payload = error.response.json()
        return isinstance(payload, dict) and payload.get("outcome") == "unknown"
    except ValueError:
        return False


def _operation_error(action: str, details: dict[str, str], error: httpx.HTTPError) -> Any:
    if isinstance(error, UNCERTAIN_TRANSPORT_ERRORS) or _reported_unknown(error):
        return _unknown_outcome(action, details)
    _audit(action, False, details)
    raise error


@ca_web.get("/certificates")
@admin_required
def index() -> Any:
    """List the agent's public issuance inventory."""
    return _render_inventory(
        _client(),
        request_id=_request_id(request.args.get("request_id")),
        days=request.args.get("days", "365"),
    )


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
    """Approve a CSR and preserve its operation identity across uncertain responses."""
    client = _client()
    if client.read_only():
        abort(403)
    if request.form.get("confirm") != "yes":
        abort(400)
    details = {"request_id": _request_id()}
    try:
        result = client.post(
            "certificates",
            {
                "csr": request.form.get("csr", ""),
                "days": request.form.get("days", "365"),
                "request_id": details["request_id"],
            },
            timeout=60,
        )
    except httpx.HTTPError as error:
        return _operation_error("issue", details, error)
    except ValueError:
        return _unknown_outcome("issue", details)
    details["certificate_id"] = str(result["id"])
    certificate = result.get("certificate", {})
    if isinstance(certificate, dict) and certificate.get("serial"):
        details["serial"] = str(certificate["serial"])
    _audit("issue", True, details)
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
    details = {"certificate_id": identifier}
    try:
        client.post(
            f"certificates/{identifier}/revoke",
            {"reason": request.form.get("reason", "0")},
            timeout=60,
        )
    except httpx.HTTPError as error:
        return _operation_error("revoke", details, error)
    _audit("revoke", True, details)
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
    details = {"serial": request.form.get("serial", "")}
    try:
        client.post(
            "revoke",
            {"serial": request.form.get("serial", ""), "reason": request.form.get("reason", "0")},
            timeout=60,
        )
    except httpx.HTTPError as error:
        return _operation_error("revoke", details, error)
    _audit("revoke", True, details)
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
    filename = {"crl": "certificate-revocation-list.pem", "root": "root-ca.pem"}.get(
        identifier, "certificate-chain.pem"
    )
    return Response(
        result["pem"],
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
