"""Ingress-only first-run account creation, without browser-side service secrets."""

from __future__ import annotations

import secrets
from typing import Any

from argon2 import PasswordHasher
from flask import Flask, Response, abort, render_template, request
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import PasswordField
from wtforms.validators import DataRequired, EqualTo, Length

from netadmin.ingress import configure_ingress
from netadmin.preferences import read_env_file, write_env_file
from netadmin.presentation import display_time

SETUP_TEMPLATE = "setup.html"


class RootForm(FlaskForm):  # type: ignore[misc]
    """Create the account needed to configure connections after first start."""

    password = PasswordField("Root password", validators=[DataRequired(), Length(min=12, max=1024)])
    confirm = PasswordField(
        "Confirm root password", validators=[DataRequired(), EqualTo("password")]
    )


def step1() -> Any:
    """Create the root account once; configure external services after login."""
    if read_env_file().get("NETADMIN_SECRET_KEY"):
        return render_template(SETUP_TEMPLATE, step="done")
    form = RootForm()
    if form.validate_on_submit():
        write_env_file(
            {
                "NETADMIN_SECRET_KEY": secrets.token_hex(32),
                "NETADMIN_ROOT_PASSWORD_HASH": PasswordHasher().hash(form.password.data or ""),
                "NETADMIN_DNS_ENABLED": "false",
                "NETADMIN_DHCP_ENABLED": "false",
                "NETADMIN_RADIUS_ENABLED": "false",
            }
        )
        return render_template(SETUP_TEMPLATE, step="done")
    return render_template(SETUP_TEMPLATE, step=1, form=form)


def create_setup_app() -> Flask:
    """Create the unconfigured Home Assistant app."""
    app = Flask(__name__)
    app.add_template_filter(display_time, "display_time")
    configure_ingress(app)
    app.config.update(
        SECRET_KEY=secrets.token_urlsafe(32),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=65_536,
    )

    @app.before_request
    def guard() -> None:
        """Hide setup outside Supervisor ingress, before CSRF processing."""
        if not request.headers.get("X-Ingress-Path"):
            abort(404)

    CSRFProtect(app)

    @app.errorhandler(ValueError)
    def bad_env_file(_error: ValueError) -> Response:
        """Keep file contents and parser errors out of the response."""
        return Response(
            "Check NETADMIN_ENV_FILE: it must be absolute and free of '..', with valid text.",
            status=500,
            mimetype="text/plain",
        )

    app.add_url_rule("/", view_func=step1, methods=["GET", "POST"])
    return app
