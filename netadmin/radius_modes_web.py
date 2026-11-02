"""Administrative authentication choices and conditional certificate navigation."""

from __future__ import annotations

from typing import Any, cast

import httpx
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from netadmin.auth import admin_required, current_identity, extension
from netadmin.services.agents import AgentClient
from netadmin.services.radius_modes import MODES
from netadmin.store import Store

modes_web = Blueprint("radius_modes", __name__)


def authentication_status() -> dict[str, Any]:
    """Unknown agents retain certificate access; never claim unused without evidence."""
    try:
        value = cast(AgentClient, extension("netadmin_radius")).get("authentication")
        if isinstance(value, dict) and isinstance(value.get("available"), bool):
            return value
    except httpx.HTTPError:
        pass
    return {
        "available": False,
        "uses_certificates": None,
        "can_manage": False,
        "reason": "Update the RADIUS agent or check its connection to view authentication modes.",
    }


@modes_web.app_context_processor
def navigation() -> dict[str, Any]:
    """Fetch mode metadata only for the RADIUS landing page."""
    return (
        {"authentication": authentication_status()}
        if request.endpoint == "web.radius_index" and getattr(g.identity, "role", "") == "admin"
        else {}
    )


@modes_web.before_app_request
def hide_unused_certificates() -> Any:
    """Allow explicit preparation while keeping unused certificate details out of normal UI."""
    if (
        request.endpoint == "radius_certificates.index"
        and getattr(getattr(g, "identity", None), "role", "") == "admin"
        and request.args.get("prepare") != "1"
        and authentication_status().get("uses_certificates") is False
    ):
        return redirect(url_for("radius_modes.index"))
    return None


@modes_web.route("/radius/authentication", methods=["GET", "POST"])
@admin_required
def index() -> Any:
    """Keep credential and service configuration writes on the restricted agent."""
    client = cast(AgentClient, extension("netadmin_radius"))
    read_only = client.read_only()
    if request.method == "POST":
        if read_only:
            abort(403)
        if request.form.get("confirm") != "yes":
            abort(400, "Confirm that devices may need updated connection profiles.")
        payload = {
            "enabled": request.form.getlist("enabled"),
            "preferred": request.form.get("preferred", ""),
            "revision": request.form.get("revision", ""),
        }
        success = False
        try:
            client.post("authentication", payload, timeout=60)
            success = True
        except httpx.HTTPStatusError as error:
            if error.response.status_code not in {400, 409, 502}:
                raise
            if error.response.status_code == 502:
                flash(
                    "The authentication change failed and rollback was attempted. "
                    "Check the RADIUS service status before trying again.",
                    "warning",
                )
                return redirect(url_for("radius_modes.index"))
            flash(
                "Settings could not be applied. Reload the page, check your selection and "
                "make sure certificates are valid before enabling PEAP or EAP-TLS.",
                "warning",
            )
        finally:
            cast(Store, extension("netadmin_store")).audit(
                current_identity().username, "radius.authentication.update", "EAP modes", success
            )
        if success:
            flash(
                "Authentication modes applied and RADIUS restarted. "
                "Update device profiles to use your selected modes.",
                "success",
            )
        return redirect(url_for("radius_modes.index"))
    return render_template(
        "radius_modes.html",
        authentication=authentication_status(),
        modes=MODES,
        read_only=read_only,
    )
