"""Flask application factory and web routes."""

from __future__ import annotations

import os
from typing import Any, cast

import httpx
from flask import Blueprint, Flask, flash, g, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect

from netadmin.auth import (
    admin_required,
    authenticate_radius,
    current_identity,
    extension,
    load_identity,
    login_required,
    safe_next_url,
    verify_root,
)
from netadmin.config import Settings
from netadmin.connections import connection_extensions
from netadmin.forms import (
    DeleteDnsForm,
    DhcpSubnetForm,
    DnsRecordForm,
    DnsZoneForm,
    LoginForm,
    PasswordForm,
    RadiusClientForm,
    RadiusUserForm,
    ReservationForm,
    RpiRecordForm,
)
from netadmin.ingress import configure_ingress
from netadmin.presentation import display_time
from netadmin.services.agents import AgentClient
from netadmin.settings_web import connection_web
from netadmin.store import Store

web = Blueprint("web", __name__)

# Endpoint names for url_for(); constants keep each literal in a single place.
DNS_INDEX = "web.dns_index"
DHCP_INDEX = "web.dhcp_index"
RADIUS_INDEX = "web.radius_index"


def _settings() -> Settings:
    return cast(Settings, extension("netadmin_settings"))


def _store() -> Store:
    return cast(Store, extension("netadmin_store"))


def _audit(action: str, target: str, success: bool = True) -> None:
    identity = current_identity()
    _store().audit(identity.username, action, target, success)


@web.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Authenticate root locally or a user through RADIUS."""
    if g.identity is not None and g.identity.source == "ingress":
        return redirect(url_for("web.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        username = (form.username.data or "").strip()
        bucket = f"login:{request.remote_addr}:{username.casefold()}"
        if not _store().allow_attempt(bucket, 5, 300):
            _store().audit(username, "login.rate_limited", username, False)
            return render_template("login.html", form=form), 429
        supplied_password = form.password.data or ""
        settings = _settings()
        role = (
            "admin"
            if username == "root" and verify_root(settings.root_password_hash, supplied_password)
            else authenticate_radius(username, supplied_password, settings)
        )
        if role:
            session_id = _store().create_session(username, role, settings.session_minutes * 60)
            _store().audit(username, "login", username, True)
            response = redirect(safe_next_url(request.args.get("next")))
            response.set_cookie(
                "netadmin_session",
                session_id,
                secure=True,
                httponly=True,
                samesite="Strict",
                max_age=None,
                path=request.script_root or "/",
            )
            return response
        _store().audit(username, "login", username, False)
        flash("Invalid username, password, or authorization role.", "danger")
    return render_template("login.html", form=form)


@web.route("/logout", methods=["POST"])
@login_required
def logout() -> Any:
    """Invalidate the current session."""
    if current_identity().source == "ingress":
        flash("Your session is managed by Home Assistant. Sign out there to end it.", "info")
        return redirect(url_for("web.dashboard"))
    session_id = request.cookies.get("netadmin_session", "")
    _audit("logout", current_identity().username)
    _store().delete_session(session_id)
    response = redirect(url_for("web.login"))
    response.delete_cookie("netadmin_session", path=request.script_root or "/")
    return response


@web.route("/", methods=["GET"])
@login_required
def dashboard() -> Any:
    """Render the role-aware landing page."""
    runtime = _settings()
    return render_template(
        "dashboard.html",
        enabled_count=sum((runtime.dns_enabled, runtime.dhcp_enabled, runtime.radius_enabled)),
        checks=extension("netadmin_connection_results"),
        events=_store().recent_audit(5) if current_identity().role == "admin" else [],
    )


@web.route("/dns", methods=["GET"])
@admin_required
def dns_index() -> Any:
    """Show records for a selected authoritative zone."""
    zone = request.args.get("zone", "")
    records = extension("netadmin_dns").records(zone) if zone else []
    return render_template(
        "dns.html",
        zones=extension("netadmin_dns").zones(),
        zone=zone,
        records=records,
        record_form=DnsRecordForm(),
        delete_form=DeleteDnsForm(),
        rpi_form=RpiRecordForm(),
        zone_form=DnsZoneForm(),
        zone_management=bool(_settings().dns_agent_url),
    )


@web.route("/dns/zones", methods=["POST"])
@admin_required
def dns_zone_create() -> Any:
    """Create a zone only through the configured privileged DNS agent."""
    agent = extension("netadmin_dns").zone_agent
    if agent is None:
        flash("Configure a DNS agent to manage zones.", "warning")
    else:
        form = DnsZoneForm()
        if form.validate_on_submit():
            agent.post("zones", {"name": form.name.data, "content": form.content.data})
            _audit("dns.zone.create", form.name.data or "")
            flash("Zone created and Bind reconfigured.", "success")
        else:
            flash("Provide a valid zone name and complete zone file.", "danger")
    return redirect(url_for(DNS_INDEX))


@web.route("/dns/zones/delete", methods=["POST"])
@admin_required
def dns_zone_remove() -> Any:
    """Remove a served zone while preserving its on-disk data."""
    agent = extension("netadmin_dns").zone_agent
    zone = request.form.get("zone", "")
    if agent is None or not zone:
        flash("Configure a DNS agent and select a zone first.", "warning")
    else:
        agent.post("zones/delete", {"name": zone})
        _audit("dns.zone.delete", zone)
        flash("Zone removed from Bind. Its data and journal were retained.", "success")
    return redirect(url_for(DNS_INDEX))


@web.route("/dns/records", methods=["POST"])
@admin_required
def dns_save() -> Any:
    """Create or replace a DNS RRset."""
    form = DnsRecordForm()
    if form.validate_on_submit():
        extension("netadmin_dns").upsert(
            (form.zone.data or "").rstrip("."),
            form.name.data or "",
            form.record_type.data or "",
            int(form.ttl.data or "300"),
            form.value.data or "",
        )
        _audit("dns.upsert", f"{form.name.data}.{form.zone.data}/{form.record_type.data}")
        flash("DNS record saved.", "success")
    else:
        flash("Invalid DNS record.", "danger")
    return redirect(url_for(DNS_INDEX, zone=form.zone.data))


@web.route("/dns/records/delete", methods=["POST"])
@admin_required
def dns_delete() -> Any:
    """Delete a DNS value or RRset."""
    form = DeleteDnsForm()
    if form.validate_on_submit():
        extension("netadmin_dns").delete(
            form.zone.data, form.name.data, form.record_type.data, form.value.data
        )
        _audit("dns.delete", f"{form.name.data}.{form.zone.data}/{form.record_type.data}")
        flash("DNS record deleted.", "success")
    return redirect(url_for(DNS_INDEX, zone=form.zone.data))


@web.route("/dns/rpi", methods=["POST"])
@admin_required
def dns_add_rpi() -> Any:
    """Create a paired forward and reverse Raspberry Pi entry."""
    form = RpiRecordForm()
    if form.validate_on_submit():
        extension("netadmin_dns").add_host(
            form.hostname.data or "",
            form.address.data or "",
            form.forward_zone.data or "",
            form.reverse_zone.data or "",
            int(form.ttl.data or "300"),
        )
        _audit("dns.rpi.create", f"{form.hostname.data}/{form.address.data}")
        flash("Forward and reverse records created.", "success")
    return redirect(url_for(DNS_INDEX, zone=form.forward_zone.data))


@web.route("/dhcp", methods=["GET", "POST"])
@admin_required
def dhcp_index() -> Any:
    """List leases and manage reservations through the DHCP agent."""
    client = cast(AgentClient, extension("netadmin_dhcp"))
    form = ReservationForm()
    if form.validate_on_submit():
        client.post(
            "reservations",
            {"name": form.name.data, "mac": form.mac.data, "address": form.address.data},
        )
        _audit("dhcp.reservation.upsert", form.name.data or "")
        flash("Reservation saved.", "success")
        return redirect(url_for(DHCP_INDEX))
    return render_template(
        "dhcp.html",
        form=form,
        subnet_form=DhcpSubnetForm(),
        reservations=client.get("reservations"),
        leases=client.get("leases"),
        subnets=client.get("configuration"),
        backend=_settings().dhcp_backend,
    )


@web.route("/dhcp/reservations/delete", methods=["POST"])
@admin_required
def dhcp_delete() -> Any:
    """Delete a managed DHCP reservation."""
    name = request.form.get("name", "")
    cast(AgentClient, extension("netadmin_dhcp")).post("reservations/delete", {"name": name})
    _audit("dhcp.reservation.delete", name)
    return redirect(url_for(DHCP_INDEX))


@web.route("/dhcp/configuration", methods=["POST"])
@admin_required
def dhcp_configuration_save() -> Any:
    """Update ranges and options for one ISC DHCPD subnet."""
    form = DhcpSubnetForm()
    if form.validate_on_submit():
        lines = [line.strip() for line in (form.ranges.data or "").splitlines() if line.strip()]
        if any(line.count("-") != 1 for line in lines):
            flash("Enter each pool as start-end. No changes were applied.", "danger")
            return redirect(url_for(DHCP_INDEX))
        ranges = [[part.strip() for part in line.split("-", 1)] for line in lines]
        options = {
            name.strip(): value.strip()
            for line in (form.options.data or "").splitlines()
            if "=" in line
            for name, value in [line.split("=", 1)]
        }
        cast(AgentClient, extension("netadmin_dhcp")).post(
            "configuration",
            {"network": form.network.data, "ranges": ranges, "options": options},
        )
        _audit("dhcp.subnet.update", form.network.data or "")
        flash("DHCP subnet configuration updated.", "success")
    return redirect(url_for(DHCP_INDEX))


@web.route("/dhcp/export/kea", methods=["GET"])
@admin_required
def dhcp_export_kea() -> Any:
    """Return a current Kea migration snapshot."""
    return cast(AgentClient, extension("netadmin_dhcp")).get("export/kea")


@web.route("/radius", methods=["GET", "POST"])
@admin_required
def radius_index() -> Any:
    """Manage file-backed RADIUS users."""
    client = cast(AgentClient, extension("netadmin_radius"))
    form = RadiusUserForm()
    if form.validate_on_submit():
        client.post(
            "users",
            {
                "username": form.username.data,
                "password": form.password.data,
                "role": form.role.data,
                "disabled": form.disabled.data,
            },
        )
        _audit("radius.user.upsert", form.username.data or "")
        flash("RADIUS user saved.", "success")
        return redirect(url_for(RADIUS_INDEX))
    return render_template(
        "radius.html",
        form=form,
        client_form=RadiusClientForm(),
        users=client.get("users"),
        clients=client.get("clients"),
        migration=client.get("migration"),
    )


@web.route("/radius/users/delete", methods=["POST"])
@admin_required
def radius_user_delete() -> Any:
    """Delete a NetAdmin-managed RADIUS user."""
    username = request.form.get("username", "")
    cast(AgentClient, extension("netadmin_radius")).post("users/delete", {"username": username})
    _audit("radius.user.delete", username)
    return redirect(url_for(RADIUS_INDEX))


@web.route("/radius/clients", methods=["POST"])
@admin_required
def radius_client_save() -> Any:
    """Create or update a managed RADIUS client."""
    form = RadiusClientForm()
    if form.validate_on_submit():
        cast(AgentClient, extension("netadmin_radius")).post(
            "clients",
            {
                "name": form.name.data,
                "address": form.address.data,
                "shortname": form.shortname.data,
                "secret": form.secret.data,
            },
        )
        _audit("radius.client.upsert", form.name.data or "")
        flash("RADIUS client saved.", "success")
    return redirect(url_for(RADIUS_INDEX))


@web.route("/radius/clients/delete", methods=["POST"])
@admin_required
def radius_client_delete() -> Any:
    """Delete a managed RADIUS client."""
    name = request.form.get("name", "")
    cast(AgentClient, extension("netadmin_radius")).post("clients/delete", {"name": name})
    _audit("radius.client.delete", name)
    return redirect(url_for(RADIUS_INDEX))


@web.route("/radius/migrate", methods=["POST"])
@admin_required
def radius_migrate() -> Any:
    """Hash legacy passwords and install explicit role attributes."""
    result = cast(AgentClient, extension("netadmin_radius")).post("migration", {})
    _audit("radius.users.migrate", str(result.get("count", 0)))
    flash(f"Migrated {result.get('count', 0)} RADIUS users.", "success")
    return redirect(url_for(RADIUS_INDEX))


@web.route("/password", methods=["GET", "POST"])
@login_required
def password() -> Any:
    """Allow a RADIUS user to change only their own password."""
    identity = current_identity()
    form = PasswordForm()
    if identity.source == "ingress":
        flash("Manage your Home Assistant password in your Home Assistant profile.", "info")
        return redirect(url_for("web.dashboard"))
    if identity.username == "root":
        flash("The emergency root password is managed through its environment hash.", "info")
        return redirect(url_for("web.dashboard"))
    if form.validate_on_submit():
        if not _store().allow_attempt(f"password:{identity.username}", 5, 900):
            flash("Too many password-change attempts. Try again later.", "danger")
            return render_template("password.html", form=form), 429
        if (
            authenticate_radius(identity.username, form.current_password.data or "", _settings())
            is None
        ):
            flash("Current password is incorrect.", "danger")
        else:
            cast(AgentClient, extension("netadmin_radius")).post(
                "users/password",
                {"username": identity.username, "password": form.new_password.data},
            )
            _audit("radius.password.change", identity.username)
            _store().delete_user_sessions(identity.username)
            response = redirect(url_for("web.login"))
            response.delete_cookie("netadmin_session", path=request.script_root or "/")
            flash("Password changed. Sign in again.", "success")
            return response
    return render_template("password.html", form=form)


@web.route("/audit", methods=["GET"])
@admin_required
def audit() -> Any:
    """Show recent audit records."""
    return render_template("audit.html", events=_store().recent_audit())


def create_app(settings: Settings | None = None) -> Flask:
    """Create and configure NetAdmin."""
    runtime = settings or Settings.from_env()
    app = Flask(__name__)
    app.add_template_filter(display_time, "display_time")
    if os.getenv("NETADMIN_ADDON") == "1":
        configure_ingress(app)
    app.config.update(
        SECRET_KEY=runtime.secret_key,
        WTF_CSRF_TIME_LIMIT=3600,
        MAX_CONTENT_LENGTH=1_048_576,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    CSRFProtect(app)
    store = Store(runtime.data_dir / "netadmin.sqlite3")
    app.extensions.update(netadmin_store=store, **connection_extensions(runtime))
    app.before_request(load_identity)
    app.register_blueprint(web)
    app.register_blueprint(connection_web)

    @app.context_processor
    def connection_context() -> dict[str, Any]:
        return {"service_settings": _settings()}

    @app.before_request
    def disabled_service() -> Any:
        """Avoid backend calls for services the administrator disabled."""
        if g.identity is not None and g.identity.role == "admin":
            for service in ("dns", "dhcp", "radius"):
                if (request.endpoint or "").startswith(f"web.{service}_") and not getattr(
                    _settings(), f"{service}_enabled"
                ):
                    flash(f"{service.upper()} is disabled. Enable it in Settings first.", "info")
                    return redirect(url_for("connections.settings_page"))
        return None

    @app.errorhandler(httpx.HTTPError)
    @app.errorhandler(RuntimeError)
    def service_error(error: Exception) -> tuple[str, int]:
        app.logger.exception("Backend service operation failed", exc_info=error)
        return render_template(
            "error.html", message="A network service is unavailable or rejected the change."
        ), 502

    return app
