"""Administrator connection settings; service files remain agent-owned."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, cast

import dns.exception
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for  # pylint: disable=wrong-import-order

from netadmin.auth import admin_required, current_identity, extension
from netadmin.config import Settings
from netadmin.connections import (
    BOOLEAN_FIELDS,
    CONNECTION_FIELDS,
    SECRET_FIELDS,
    SECTIONS,
    ConnectionForm,
    configuration_errors,
    connection_extensions,
    connection_values,
    env_key,
    normalize_connection,
    settings_with_connections,
    test_connection,
)
from netadmin.preferences import read_env_file, write_env_file
from netadmin.store import Store

connection_web = Blueprint("connections", __name__)
ERROR_TEMPLATE = "error.html"


@connection_web.route("/settings", methods=["GET", "POST"])
@admin_required
def settings_page() -> Any:
    """Persist and activate app connections, leaving secrets masked."""
    runtime = cast(Settings, extension("netadmin_settings"))
    active = connection_values(runtime)
    editable = os.getenv("NETADMIN_ADDON") == "1"
    try:
        saved = read_env_file() if editable else {}
    except (OSError, ValueError):
        return render_template(
            ERROR_TEMPLATE,
            message="Cannot read the app settings file. Check its path and permissions.",
        ), 503
    previous = {
        field: normalize_connection(field, saved.get(env_key(field), value))
        for field, value in active.items()
    }
    data = {
        field: value == "true" if field in BOOLEAN_FIELDS else value
        for field, value in previous.items()
        if field not in SECRET_FIELDS
    }
    form = ConnectionForm(data=data)
    if request.method == "POST":
        if not editable:
            return render_template(
                ERROR_TEMPLATE,
                message="Standalone settings are managed through environment variables.",
            ), 403
        if form.validate_on_submit():
            values = form.values(previous)
            if form.check_connections(values):
                try:
                    replacements = connection_extensions(settings_with_connections(runtime, values))
                    write_env_file({env_key(field): value for field, value in values.items()})
                except (OSError, ValueError, dns.exception.DNSException):
                    return render_template(
                        ERROR_TEMPLATE,
                        message="Could not save settings. Check the configuration directory.",
                    ), 503
                current_app.extensions.update(replacements)
                cast(Store, extension("netadmin_store")).audit(
                    current_identity().username, "settings.connections", "connections", True
                )
                flash("Settings saved and applied. No restart needed.", "success")
                return redirect(url_for("connections.settings_page"))
    pending = any(previous[field] != active[field] for field in CONNECTION_FIELDS)
    return render_template(
        "settings.html",
        form=form,
        sections=SECTIONS,
        secrets={name: bool(previous[name]) for name in SECRET_FIELDS},
        editable=editable,
        pending=pending,
    )


@connection_web.route("/settings/test/<any(dns,dhcp,radius):service>", methods=["POST"])
@admin_required
def connection_test(service: str) -> Any:
    """Run a user-requested read-only test against the active configuration."""
    runtime = cast(Settings, extension("netadmin_settings"))
    result = test_connection(runtime, service)
    current_app.extensions["netadmin_connection_results"][service] = {
        "result": result,
        "checked_at": int(datetime.now(UTC).timestamp()),
    }
    return render_template("connection_test.html", service=service.upper(), result=result)


@connection_web.route("/settings/reload", methods=["POST"])
@admin_required
def reload_connections() -> Any:
    """Reload connection assignments after a manual file edit, without restarting."""
    if os.getenv("NETADMIN_ADDON") != "1":
        return render_template(
            ERROR_TEMPLATE,
            message="Restart standalone deployments to reload environment variables.",
        ), 403
    runtime = cast(Settings, extension("netadmin_settings"))
    try:
        saved = read_env_file()
        values = {
            field: normalize_connection(field, saved.get(env_key(field), value))
            for field, value in connection_values(runtime).items()
        }
        if configuration_errors(values):
            return render_template(
                ERROR_TEMPLATE,
                message=(
                    "Invalid saved connections. Correct them in Settings. "
                    "Active connections were kept."
                ),
            ), 400
        replacements = connection_extensions(settings_with_connections(runtime, values))
    except (OSError, ValueError, dns.exception.DNSException):
        return render_template(
            ERROR_TEMPLATE,
            message="Could not reload saved connections. Active connections were kept.",
        ), 503
    current_app.extensions.update(replacements)
    cast(Store, extension("netadmin_store")).audit(
        current_identity().username, "settings.reload", "connections", True
    )
    flash("Saved connections reloaded. No restart needed.", "success")
    return redirect(url_for("connections.settings_page"))
