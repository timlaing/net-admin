"""Validated connection settings and read-only service diagnostics."""

from __future__ import annotations

import base64
import binascii
import socket
import ssl
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import httpx  # pylint: disable=wrong-import-order
from flask_wtf import FlaskForm  # pylint: disable=wrong-import-order
from wtforms import BooleanField, PasswordField, SelectField, StringField  # pylint: disable=wrong-import-order
from wtforms.validators import Length, Regexp  # pylint: disable=wrong-import-order

from netadmin.config import Settings
from netadmin.services.agents import AgentClient
from netadmin.services.dns import BindService

SECRET_FIELDS = ("dns_tsig_secret", "radius_secret", "agent_token")
PATH_FIELDS = ("dns_config_path", "agent_ca", "agent_cert", "agent_key")
SECTIONS = {
    "DNS": ("dns_enabled", "dns_server", "dns_zones", "dns_tsig_secret"),
    "DHCP": ("dhcp_enabled", "dhcp_agent_url", "dhcp_backend"),
    "RADIUS": ("radius_enabled", "radius_agent_url", "radius_host", "radius_secret"),
    "Agent security": ("agent_token", "agent_ca", "agent_cert", "agent_key"),
    "Advanced DNS": ("dns_tsig_name", "dns_tsig_algorithm", "dns_config_path"),
}
CONNECTION_FIELDS = tuple(field for fields in SECTIONS.values() for field in fields)


def env_key(field: str) -> str:
    """Map a connection field to its existing environment variable."""
    return f"NETADMIN_{field.upper()}"


def normalize_connection(field: str, value: str) -> str:
    """Use the same spelling as Settings.from_env for restart comparisons."""
    if field == "dns_zones":
        return ",".join(zone.strip() for zone in value.split(",") if zone.strip())
    if field in PATH_FIELDS and value:
        return str(Path(value))
    return value


def connection_values(settings: Settings) -> dict[str, str]:
    """Serialize connections for persistence; never place these in a cookie."""
    data = asdict(settings)
    return {
        field: ",".join(value)
        if isinstance(value, tuple)
        else str(value).lower()
        if isinstance(value, bool)
        else str(value or "")
        for field in CONNECTION_FIELDS
        for value in [data[field]]
    }


def settings_with_connections(settings: Settings, values: dict[str, str]) -> Settings:
    """Replace only connection fields, keeping accounts and sessions intact."""
    changes: dict[str, Any] = dict(values)
    for field in CONNECTION_FIELDS:
        if field.endswith("_enabled"):
            changes[field] = values[field] == "true"
        elif field in PATH_FIELDS:
            changes[field] = Path(values[field]) if values[field] else None
        elif field == "dns_zones":
            changes[field] = tuple(zone for zone in values[field].split(",") if zone)
    return replace(settings, **changes)


def connection_extensions(settings: Settings) -> dict[str, Any]:
    """Construct replacements before changing any active app references."""
    return {
        "netadmin_connection_results": {},
        "netadmin_settings": settings,
        "netadmin_dns": BindService(
            settings.dns_server,
            settings.dns_tsig_name,
            settings.dns_tsig_secret if settings.dns_enabled else "",
            settings.dns_tsig_algorithm,
            settings.dns_config_path,
            settings.dns_zones,
        ),
        "netadmin_dhcp": AgentClient(
            settings.dhcp_agent_url,
            settings.agent_token,
            settings.agent_ca,
            settings.agent_cert,
            settings.agent_key,
        ),
        "netadmin_radius": AgentClient(
            settings.radius_agent_url,
            settings.agent_token,
            settings.agent_ca,
            settings.agent_cert,
            settings.agent_key,
        ),
    }


def text_field(label: str, maximum: int = 253) -> StringField:
    """Create a single-line optional setting; enabled services add requirements."""
    return StringField(label, validators=[Length(max=maximum), Regexp(r"^[^\r\n\x00]*$")])


class ConnectionForm(FlaskForm):  # type: ignore[misc]
    """One administrator form for all service connections."""

    dns_enabled = BooleanField("Enable DNS administration")
    dns_server = text_field("Bind server")
    dns_zones = text_field("Authoritative zones (comma separated)", 1024)
    dns_tsig_secret = PasswordField("TSIG secret", validators=[Length(max=512)])
    dns_tsig_name = text_field("TSIG key name")
    dns_tsig_algorithm = SelectField(
        "TSIG algorithm",
        choices=[
            ("hmac-sha256", "HMAC SHA-256"),
            ("hmac-sha512", "HMAC SHA-512"),
            ("hmac-sha1", "HMAC SHA-1 (legacy)"),
            ("hmac-md5.sig-alg.reg.int", "HMAC MD5 (legacy)"),
        ],
    )
    dns_config_path = text_field("Local Bind configuration path (optional)", 1024)
    dhcp_enabled = BooleanField("Enable DHCP administration")
    dhcp_agent_url = text_field("DHCP agent HTTPS URL")
    dhcp_backend = SelectField("DHCP backend", choices=[("isc", "ISC DHCPD"), ("kea", "Kea")])
    radius_enabled = BooleanField("Enable RADIUS administration and login")
    radius_agent_url = text_field("RADIUS agent HTTPS URL")
    radius_host = text_field("RADIUS authentication server")
    radius_secret = PasswordField("RADIUS shared secret", validators=[Length(max=253)])
    agent_token = PasswordField("Shared agent bearer token", validators=[Length(max=1024)])
    agent_ca = text_field("CA certificate path (blank for system trust)", 1024)
    agent_cert = text_field("Client certificate path", 1024)
    agent_key = text_field("Client private key path", 1024)

    def values(self, previous: dict[str, str]) -> dict[str, str]:
        """Preserve existing secrets when their password inputs are left blank."""
        result = {}
        for field in CONNECTION_FIELDS:
            value = self[field].data
            if field in SECRET_FIELDS:
                result[field] = value or previous.get(field, "")
            else:
                result[field] = (
                    str(value).lower() if isinstance(value, bool) else (value or "").strip()
                )
        return {field: normalize_connection(field, value) for field, value in result.items()}

    def check_connections(self, values: dict[str, str]) -> bool:
        """Attach actionable validation errors without echoing secret input."""
        errors = configuration_errors(values)
        for name, message in errors.items():
            self[name].errors = [*self[name].errors, message]
        return not errors


def configuration_errors(values: dict[str, str]) -> dict[str, str]:
    """Validate enabled-service prerequisites before accepting a configuration."""
    errors = {}
    for service in ("dns", "dhcp", "radius"):
        field = f"{service}_enabled"
        if values[field] not in {"true", "false"}:
            errors[field] = "Choose true or false."
    if values["dhcp_backend"] not in {"isc", "kea"}:
        errors["dhcp_backend"] = "Choose ISC DHCPD or Kea."
    for field in SECRET_FIELDS:
        if any(char in values[field] for char in "\r\n\x00"):
            errors[field] = "Use a single-line secret."
    for field in PATH_FIELDS:
        value = values[field]
        if value and (not Path(value).is_absolute() or ".." in Path(value).parts):
            errors[field] = "Use an absolute path without '..'."
    errors.update(_agent_errors(values))
    errors.update(_dns_errors(values))
    return errors


def _agent_errors(values: dict[str, str]) -> dict[str, str]:
    """Validate agent transport and RADIUS authentication requirements."""
    errors: dict[str, str] = {}
    for service in ("dhcp", "radius"):
        if values[f"{service}_enabled"] != "true":
            continue
        field = f"{service}_agent_url"
        try:
            parsed = urlsplit(values[field])
            valid = (
                parsed.scheme == "https"
                and parsed.hostname
                and parsed.port != 0
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            valid = False
        if not valid:
            errors[field] = "Enter an HTTPS agent URL without credentials, query or fragment."
        for name in ("agent_token", "agent_cert", "agent_key"):
            if not values[name]:
                errors[name] = "Required for enabled agents using mTLS and bearer authentication."
    if values["radius_enabled"] == "true":
        for name in ("radius_host", "radius_secret"):
            if not values[name]:
                errors[name] = "Required for RADIUS authentication."
    return errors


def _dns_errors(values: dict[str, str]) -> dict[str, str]:
    """Validate the authoritative DNS connection."""
    errors: dict[str, str] = {}
    if values["dns_enabled"] == "true":
        for name in ("dns_server", "dns_tsig_name", "dns_tsig_secret"):
            if not values[name]:
                errors[name] = "Required for authenticated Bind administration."
        if (
            not normalize_connection("dns_zones", values["dns_zones"])
            and not values["dns_config_path"]
        ):
            errors["dns_zones"] = (
                "Enter your zones; remote Bind zones cannot be discovered automatically."
            )
        if values["dns_tsig_secret"]:
            try:
                base64.b64decode(values["dns_tsig_secret"], validate=True)
            except (ValueError, binascii.Error):
                errors["dns_tsig_secret"] = "Enter the base64 secret from your existing TSIG key."  # noqa: S105
    return errors


@dataclass(frozen=True)
class ConnectionResult:
    """A bounded test result, with no raw exceptions or credentials."""

    state: str
    message: str


def test_connection(settings: Settings, service: str) -> ConnectionResult:
    """Test active settings only; never mutate a remote service."""
    values = connection_values(settings)
    if values[f"{service}_enabled"] != "true":
        return ConnectionResult("Disabled", "Enable this service in Settings when you need it.")
    errors = configuration_errors(values)
    fields = set(SECTIONS[service.upper()])
    if service == "dns":
        fields.update(SECTIONS["Advanced DNS"])
    else:
        fields.update(SECTIONS["Agent security"])
    relevant = [message for field, message in errors.items() if field in fields]
    if relevant:
        return ConnectionResult("Not configured", relevant[0])
    try:
        return _probe(settings, service)
    except (
        httpx.HTTPError,
        OSError,
        dns.exception.DNSException,
        ValueError,
        RuntimeError,
    ) as error:
        return ConnectionResult("Unavailable", _failure_message(error))


def _failure_message(error: Exception) -> str:
    """Explain failures without leaking remote exception text or credentials."""
    if isinstance(error, httpx.HTTPStatusError):
        if error.response.status_code in {401, 403}:
            return "Agent rejected authentication. Check its bearer token and permissions."
        return "Agent returned an HTTP error. Check the agent logs."
    messages = [
        ((socket.gaierror,), "Hostname resolution failed. Check the server address."),
        (
            (ssl.SSLError, FileNotFoundError),
            "TLS configuration failed. Check certificate files, trust and hostname.",
        ),
        (
            (httpx.TimeoutException, dns.exception.Timeout, TimeoutError),
            "Connection timed out. Check the server, port and firewall.",
        ),
    ]
    return next(
        (message for types, message in messages if isinstance(error, types)),
        "Connection failed. Check TLS, service permissions and server logs.",
    )


def _probe(settings: Settings, service: str) -> ConnectionResult:
    """Resolve and probe one active service within the request timeout."""
    if service == "dns":
        socket.getaddrinfo(settings.dns_server, 53, type=socket.SOCK_STREAM)
        bind = BindService(
            settings.dns_server,
            settings.dns_tsig_name,
            settings.dns_tsig_secret,
            settings.dns_tsig_algorithm,
            settings.dns_config_path,
            settings.dns_zones,
        )
        zones = bind.zones()
        if not zones:
            return ConnectionResult(
                "Not configured", "No authoritative zones found. Set your zone names."
            )
        records = bind.records(zones[0].name)
        return ConnectionResult(
            "Connected",
            f"Read {len(records)} records from {zones[0].name}. "
            "Only the first zone was tested; update permissions were not tested.",
        )
    url = getattr(settings, f"{service}_agent_url")
    socket.getaddrinfo(urlsplit(url).hostname, urlsplit(url).port or 443, type=socket.SOCK_STREAM)
    client = AgentClient(
        url, settings.agent_token, settings.agent_ca, settings.agent_cert, settings.agent_key
    )
    result: Any = client.get("health")
    if not isinstance(result, dict) or result.get("status") != "ok":
        return ConnectionResult(
            "Unavailable", "Unexpected agent health response. Check the agent URL."
        )
    return ConnectionResult(
        "Connected",
        "Agent accepted TLS and bearer authentication. "
        "Daemon health and write/reload permissions were not tested.",
    )
