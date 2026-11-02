"""Administrator interface for CA-local initialization and subordinate authorities."""

from __future__ import annotations

import contextlib
import json
import uuid
from typing import Any, cast

import httpx
from flask import Blueprint, Response, abort, redirect, render_template, request, url_for

from netadmin.auth import admin_required, current_identity, extension
from netadmin.ca_runtime.store import identifier
from netadmin.config import Settings
from netadmin.services.agents import AgentClient
from netadmin.store import Store

CA_TEMPLATE = "ca_authorities.html"
authorities_web = Blueprint("authorities", __name__)


@authorities_web.errorhandler(httpx.HTTPError)
@authorities_web.errorhandler(ValueError)
def unavailable(_error: Exception) -> Any:
    """Keep malformed configuration and connection failures out of generic errors."""
    return render_template(CA_TEMPLATE, unavailable=True), 502


AUTHORITY_API = "authorities/"
PEM_CONTENT_TYPE = "application/x-pem-file"


def client() -> AgentClient:
    """Use independent management scope in addition to existing mTLS/bearer auth."""
    settings = cast(Settings, extension("netadmin_settings"))
    if not settings.ca_agent_url or not settings.ca_management_token:
        abort(409, "Configure the CA endpoint and separate management token in Settings.")
    result = AgentClient(
        settings.ca_agent_url,
        settings.agent_token,
        settings.agent_ca,
        settings.agent_cert,
        settings.agent_key,
    )
    result.headers["X-CA-Management-Token"] = settings.ca_management_token
    return result


def audit(action: str, operation_id: str, success: bool | None) -> None:
    """Audit operation identity without recording secrets or key material."""
    cast(Store, extension("netadmin_store")).audit(
        current_identity().username, "ca.authority." + action, operation_id, success
    )


@authorities_web.get("/certificates/authorities")
@admin_required
def index() -> Any:
    """Display authority hierarchy and the first-run root certificate form."""
    settings = cast(Settings, extension("netadmin_settings"))
    if not settings.ca_agent_url or not settings.ca_management_token:
        return render_template(CA_TEMPLATE, not_configured=True)
    try:
        remote = client()
        state = remote.get("authorities")
        read_only = remote.read_only()
    except httpx.HTTPError:
        return render_template(CA_TEMPLATE, unavailable=True), 502
    return render_template(
        CA_TEMPLATE,
        state=state,
        read_only=read_only,
        request_id=uuid.uuid4().hex,
        fresh_request_id=lambda: uuid.uuid4().hex,
    )


def load_recovery(body: dict[str, str]) -> None:
    """Read only bounded encrypted recovery material from an uploaded archive."""
    recovery = request.files.get("recovery_file")
    if recovery:
        try:
            data = json.loads(recovery.stream.read(32769))
            body["recovery_key"] = data["key"]
            if not isinstance(body["recovery_key"], str) or len(body["recovery_key"]) > 16384:
                abort(400)
        except (ValueError, KeyError, TypeError):
            abort(400, "Invalid recovery file")


def _operation_failure(action: str, operation_id: str, error: httpx.HTTPError) -> Any:
    """Distinguish rejected requests from interrupted or uncertain operations."""
    known_rejection = isinstance(error, httpx.HTTPStatusError) and error.response.status_code in {
        400,
        403,
        404,
    }  # pylint: disable=no-member
    message = ""
    if known_rejection:
        with contextlib.suppress(ValueError, AttributeError):
            message = str(cast(httpx.HTTPStatusError, error).response.json().get("error", ""))[:300]
    audit(action, operation_id, False if known_rejection else None)
    return render_template(
        CA_TEMPLATE, operation_error=True, request_id=operation_id, operation_message=message
    ), (400 if known_rejection else 409)


@authorities_web.post("/certificates/authorities/<action>")
@admin_required
def mutate(action: str) -> Any:
    """Forward a bounded form; no web-app signing keys or service configuration writes."""
    if action not in {"root", "subordinate", "export-root", "archive-root", "issue", "revoke"}:
        abort(404)
    try:
        operation_id = identifier(request.form.get("request_id", ""))
    except ValueError:
        abort(400)
    fields = (
        "common_name",
        "days",
        "path_length",
        "organization",
        "unit",
        "country",
        "state",
        "locality",
        "sans",
        "parent_id",
        "csr",
        "dns_suffixes",
        "ip_ranges",
        "leaf_days",
        "service_host",
        "password",
        "confirmation",
        "recovery_password",
        "recovery_key",
        "serial",
        "reason",
    )
    body = {name: request.form[name] for name in fields if name in request.form}
    body["request_id"] = operation_id
    if sum(len(value.encode()) for value in body.values()) > 100000:
        abort(413)
    load_recovery(body)
    if request.form.get("confirm") != "yes":
        abort(400, "Confirm this operation")
    remote = client()
    path = AUTHORITY_API + action
    if action in {"issue", "revoke"}:
        try:
            path = AUTHORITY_API + identifier(request.form.get("issuer_id", "")) + "/" + action
        except ValueError:
            abort(400)
    try:
        result = remote.post(path, body, timeout=100)
    except httpx.HTTPError as error:
        return _operation_failure(action, operation_id, error)
    audit(action, operation_id, True)
    if action == "export-root":
        return Response(
            json.dumps(result),
            mimetype="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="root-ca-recovery.json"',
                "Cache-Control": "no-store",
            },
        )
    if action == "issue":
        return Response(
            result["pem"],
            mimetype=PEM_CONTENT_TYPE,
            headers={
                "Content-Disposition": 'attachment; filename="certificate-chain.pem"',
                "Cache-Control": "no-store",
            },
        )
    return redirect(url_for("authorities.index"))


@authorities_web.get("/certificates/authorities/<authority_id>/chain")
@admin_required
def chain(authority_id: str) -> Any:
    """Download public certificates for a selected authority."""
    try:
        authority_id = identifier(authority_id)
    except ValueError:
        abort(404)
    result = client().get(AUTHORITY_API + authority_id + "/chain")
    return Response(
        result["pem"],
        mimetype=PEM_CONTENT_TYPE,
        headers={
            "Content-Disposition": 'attachment; filename="ca-chain.pem"',
        },
    )


@authorities_web.get("/certificates/authorities/operations/<operation_id>")
@admin_required
def operation(operation_id: str) -> Any:
    """Read durable status after interrupted initialization or signing."""
    try:
        operation_id = identifier(operation_id)
    except ValueError:
        abort(404)
    try:
        result = client().get("operations/" + operation_id)
    except httpx.HTTPError:
        return render_template(CA_TEMPLATE, unavailable=True), 502
    return render_template(CA_TEMPLATE, operation_result=result, request_id=operation_id)


@authorities_web.get("/certificates/authorities/<authority_id>/issued")
@admin_required
def issued(authority_id: str) -> Any:
    """View certificates issued through this runtime and issuer-specific revocation."""
    try:
        authority_id = identifier(authority_id)
    except ValueError:
        abort(404)
    try:
        remote = client()
        state = remote.get("authorities")
        result = remote.get(AUTHORITY_API + authority_id + "/certificates")
        read_only = remote.read_only()
    except httpx.HTTPError:
        return render_template(CA_TEMPLATE, unavailable=True), 502
    selected = next((item for item in state["authorities"] if item["id"] == authority_id), None)
    if not selected:
        abort(404)
    return render_template(
        "ca_issuer.html",
        issuer=selected,
        certificates=result["certificates"],
        read_only=read_only,
        fresh_request_id=lambda: uuid.uuid4().hex,
    )


@authorities_web.get("/certificates/authorities/<authority_id>/crl")
@admin_required
def crl(authority_id: str) -> Any:
    """Download the authoritative CRL for the selected issuing CA."""
    try:
        authority_id = identifier(authority_id)
    except ValueError:
        abort(404)
    result = client().get(AUTHORITY_API + authority_id + "/crl")
    return Response(
        result["pem"],
        mimetype=PEM_CONTENT_TYPE,
        headers={
            "Content-Disposition": 'attachment; filename="issuer-crl.pem"',
        },
    )
