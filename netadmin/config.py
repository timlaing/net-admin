"""Environment-backed application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _required(name: str) -> str:
    value = os.getenv(name, "")
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def _path_env(name: str) -> Path | None:
    """Read an optional filesystem path from the environment."""
    value = os.getenv(name, "")
    return Path(value) if value else None


def _choice(name: str, default: str, allowed: set[str]) -> str:
    """Read an environment variable restricted to a small set of values."""
    value = os.getenv(name, default)
    if value not in allowed:
        raise RuntimeError(f"{name} must be one of {sorted(allowed)}, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:  # pylint: disable=too-many-instance-attributes
    """Runtime settings shared by the web application."""

    secret_key: str
    root_password_hash: str
    data_dir: Path
    radius_host: str = "radius"
    radius_secret: str = ""
    radius_nas_ip: str = "127.0.0.1"
    radius_admin_value: str = "netadmin-admin"
    radius_standard_value: str = "netadmin-standard"
    radius_role_attribute: str = "Filter-Id"
    dns_agent_url: str = ""
    dns_server: str = "dns"
    dns_tsig_name: str = "rndc-key"
    dns_tsig_secret: str = ""
    dns_tsig_algorithm: str = "hmac-sha256"
    dns_config_path: Path | None = None
    dns_zones: tuple[str, ...] = ()
    dhcp_agent_url: str = "https://dhcp-agent:8081"
    dhcp_backend: str = "isc"
    radius_agent_url: str = "https://radius-agent:8082"
    agent_token: str = ""
    agent_ca: Path | None = None
    agent_cert: Path | None = None
    agent_key: Path | None = None
    session_minutes: int = 60
    dns_enabled: bool = True
    dhcp_enabled: bool = True
    radius_enabled: bool = True
    ingress_require_login: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        """Create settings from environment variables."""
        return cls(
            secret_key=_required("NETADMIN_SECRET_KEY"),
            root_password_hash=_required("NETADMIN_ROOT_PASSWORD_HASH"),
            data_dir=Path(os.getenv("NETADMIN_DATA_DIR", "/data")),
            radius_host=os.getenv("NETADMIN_RADIUS_HOST", "radius"),
            radius_secret=os.getenv("NETADMIN_RADIUS_SECRET", ""),
            radius_nas_ip=os.getenv("NETADMIN_RADIUS_NAS_IP", "127.0.0.1"),
            radius_admin_value=os.getenv("NETADMIN_RADIUS_ADMIN_VALUE", "netadmin-admin"),
            radius_standard_value=os.getenv("NETADMIN_RADIUS_STANDARD_VALUE", "netadmin-standard"),
            radius_role_attribute=os.getenv("NETADMIN_RADIUS_ROLE_ATTRIBUTE", "Filter-Id"),
            dns_agent_url=os.getenv("NETADMIN_DNS_AGENT_URL", ""),
            dns_server=os.getenv("NETADMIN_DNS_SERVER", "dns"),
            dns_tsig_name=os.getenv("NETADMIN_DNS_TSIG_NAME", "rndc-key"),
            dns_tsig_secret=os.getenv("NETADMIN_DNS_TSIG_SECRET", ""),
            dns_tsig_algorithm=os.getenv("NETADMIN_DNS_TSIG_ALGORITHM", "hmac-sha256"),
            dns_config_path=_path_env("NETADMIN_DNS_CONFIG_PATH"),
            dns_zones=tuple(
                item.strip()
                for item in os.getenv("NETADMIN_DNS_ZONES", "").split(",")
                if item.strip()
            ),
            dhcp_agent_url=os.getenv("NETADMIN_DHCP_AGENT_URL", "https://dhcp-agent:8081"),
            dhcp_backend=_choice("NETADMIN_DHCP_BACKEND", "isc", {"isc", "kea"}),
            radius_agent_url=os.getenv("NETADMIN_RADIUS_AGENT_URL", "https://radius-agent:8082"),
            agent_token=os.getenv("NETADMIN_AGENT_TOKEN", ""),
            agent_ca=_path_env("NETADMIN_AGENT_CA"),
            agent_cert=_path_env("NETADMIN_AGENT_CERT"),
            agent_key=_path_env("NETADMIN_AGENT_KEY"),
            session_minutes=int(os.getenv("NETADMIN_SESSION_MINUTES", "60")),
            dns_enabled=_choice("NETADMIN_DNS_ENABLED", "true", {"true", "false"}) == "true",
            dhcp_enabled=_choice("NETADMIN_DHCP_ENABLED", "true", {"true", "false"}) == "true",
            radius_enabled=_choice("NETADMIN_RADIUS_ENABLED", "true", {"true", "false"}) == "true",
            ingress_require_login=_choice(
                "NETADMIN_INGRESS_REQUIRE_LOGIN", "true", {"true", "false"}
            )
            == "true",
        )
