"""First-run setup wizard for the Home Assistant add-on (ingress only)."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from flask import Flask, abort, render_template, request, session
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired, EqualTo, Length, Optional

from netadmin.ingress import configure_ingress

MANAGED_KEYS = (
    "NETADMIN_SECRET_KEY",
    "NETADMIN_AGENT_TOKEN",
    "NETADMIN_ROOT_PASSWORD_HASH",
    "NETADMIN_RADIUS_SECRET",
    "NETADMIN_DNS_TSIG_SECRET",
    "NETADMIN_DNS_SERVER",
    "NETADMIN_DNS_ZONES",
    "NETADMIN_DHCP_AGENT_URL",
    "NETADMIN_RADIUS_AGENT_URL",
)


def env_path() -> Path:
    """Path of the environment file the add-on sources at startup."""
    candidate = Path(os.getenv("NETADMIN_ENV_FILE", "/config/netadmin.env"))
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"NETADMIN_ENV_FILE must be absolute and free of '..': {candidate}")
    return candidate


def _is_configured() -> bool:
    path = env_path()
    if not path.is_file():
        return False
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "NETADMIN_SECRET_KEY" and value.strip().strip("'\""):
            return True
    return False


def write_env_file(values: dict[str, str]) -> None:
    """Merge managed values into the environment file atomically with mode 0640."""
    path = env_path()
    existing = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            key = line.partition("=")[0].strip()
            if line.strip() and key not in MANAGED_KEYS:
                existing.append(line)
    managed = [f"{key}='{value}'" for key, value in values.items() if value]
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    # False positive (S2083): the path comes from env_path(), which raises unless
    # NETADMIN_ENV_FILE is absolute and free of '..'. The variable is set by the
    # operator at deploy time (the add-on's run.sh), never by a request, so the
    # traversal vector cannot be reached from the web layer.
    temporary.write_text("\n".join(existing + managed) + "\n", encoding="utf-8")  # NOSONAR
    temporary.chmod(0o640)
    temporary.replace(path)


class Step1Form(FlaskForm):  # type: ignore[misc]
    """Root account step."""

    password = PasswordField("Root password", validators=[DataRequired(), Length(min=12, max=1024)])
    confirm = PasswordField(
        "Confirm root password", validators=[DataRequired(), EqualTo("password")]
    )


class Step2Form(FlaskForm):  # type: ignore[misc]
    """Service endpoints and secrets step."""

    dns_server = StringField(
        "Bind server", default="dns", validators=[DataRequired(), Length(max=253)]
    )
    dns_zones = StringField(
        "Zones (comma separated, blank to discover)",
        default="",
        validators=[Length(max=1024)],
    )
    dhcp_agent_url = StringField(
        "DHCP agent URL",
        default="https://dhcp-agent:8081",
        validators=[DataRequired(), Length(max=253)],
    )
    radius_agent_url = StringField(
        "RADIUS agent URL",
        default="https://radius-agent:8082",
        validators=[DataRequired(), Length(max=253)],
    )
    radius_secret = PasswordField(
        "RADIUS shared secret (blank to generate)",
        validators=[Optional(), Length(min=8, max=253)],
    )
    tsig_secret = PasswordField(
        "TSIG secret from rndc.key (blank to set later)",
        validators=[Optional(), Length(max=512)],
    )


class Step3Form(FlaskForm):  # type: ignore[misc]
    """Review and apply step."""

    confirmed = BooleanField(
        "I have recorded the RADIUS shared secret", validators=[DataRequired()]
    )


_TEMPLATE = "setup.html"


def _render(step: Any, **context: Any) -> Any:
    """Render the setup wizard for one step."""
    return render_template(_TEMPLATE, step=step, **context)


def step1() -> Any:
    """Create the emergency root account."""
    if _is_configured():
        return _render("done")
    form = Step1Form()
    if form.validate_on_submit():
        session["setup"] = {"hash": PasswordHasher().hash(form.password.data or "")}
        return _render(2, form=Step2Form())
    return _render(1, form=form)


def step2() -> Any:
    """Collect service endpoints and secrets."""
    if "setup" not in session:
        return _render(1, form=Step1Form())
    form = Step2Form()
    if form.validate_on_submit():
        setup = session["setup"]
        setup.update(
            dns_server=(form.dns_server.data or "").strip(),
            dns_zones=(form.dns_zones.data or "").strip(),
            dhcp_agent_url=(form.dhcp_agent_url.data or "").strip(),
            radius_agent_url=(form.radius_agent_url.data or "").strip(),
            radius_secret=(form.radius_secret.data or "").strip() or secrets.token_hex(16),
            tsig_secret=(form.tsig_secret.data or "").strip(),
        )
        session["setup"] = setup
        return _render(3, form=Step3Form(), values=setup)
    return _render(2, form=form)


def apply() -> Any:
    """Write the environment file and instruct the operator to restart."""
    setup = session.get("setup")
    if not setup or _is_configured():
        return _render(1, form=Step1Form())
    form = Step3Form()
    if not form.validate_on_submit():
        return _render(3, form=form, values=setup), 400
    write_env_file(
        {
            "NETADMIN_SECRET_KEY": secrets.token_hex(32),
            "NETADMIN_AGENT_TOKEN": secrets.token_hex(32),
            "NETADMIN_ROOT_PASSWORD_HASH": setup["hash"],
            "NETADMIN_RADIUS_SECRET": setup["radius_secret"],
            "NETADMIN_DNS_TSIG_SECRET": setup.get("tsig_secret", ""),
            "NETADMIN_DNS_SERVER": setup["dns_server"],
            "NETADMIN_DNS_ZONES": setup["dns_zones"],
            "NETADMIN_DHCP_AGENT_URL": setup["dhcp_agent_url"],
            "NETADMIN_RADIUS_AGENT_URL": setup["radius_agent_url"],
        }
    )
    session.clear()
    return _render("done")


def create_setup_app() -> Flask:
    """Create the unconfigured add-on app that only serves the setup wizard."""
    app = Flask(__name__)
    configure_ingress(app)
    app.config.update(
        SECRET_KEY=secrets.token_urlsafe(32),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        WTF_CSRF_TIME_LIMIT=None,
        MAX_CONTENT_LENGTH=65_536,
    )

    # Registered before CSRFProtect: before_request hooks run in registration
    # order, so non-ingress requests must 404 here rather than surface the
    # CSRF layer's 400 and reveal that a route exists.
    @app.before_request
    def guard() -> Any:
        """Serve the wizard only through Home Assistant ingress."""
        if not request.headers.get("X-Ingress-Path"):
            abort(404)

    CSRFProtect(app)

    # env_path() refuses relative or traversal-bearing NETADMIN_ENV_FILE values;
    # report the misconfiguration instead of an unhandled 500 traceback.
    @app.errorhandler(ValueError)
    def bad_env_file(error: ValueError) -> tuple[str, int]:
        """Serve the configured-path rejection as a plain error page."""
        return str(error), 500

    app.add_url_rule("/", view_func=step1, methods=["GET", "POST"])
    app.add_url_rule("/services", view_func=step2, methods=["GET", "POST"])
    app.add_url_rule("/apply", view_func=apply, methods=["POST"])
    return app
