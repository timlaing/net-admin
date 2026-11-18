"""Health metadata stays authenticated, bounded and compatible with older agents."""

import subprocess

import httpx
import pytest

from netadmin.agents.common import create_agent
from netadmin.health import ready, version
from netadmin.services.agents import AgentClient
from tests.test_ca_runtime import runtime  # noqa: F401


def test_authenticated_version_and_readiness(monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("NETADMIN_BUILD_VERSION", "2026.11.2")
    monkeypatch.setattr("netadmin.agents.common.ready", lambda kind: kind == "dhcp")
    client = create_agent("netadmin.agents.dhcp").test_client()
    assert client.get("/ready").status_code == 401
    assert client.get("/version").status_code == 401
    headers = {"Authorization": "Bearer synthetic"}
    assert client.get("/version", headers=headers).json["version"] == "2026.11.2"
    assert client.get("/ready", headers=headers).json["ready"] is True
    monkeypatch.setattr("netadmin.agents.common.ready", lambda _kind: False)
    assert client.get("/ready", headers=headers).status_code == 503


def test_version_never_exposes_arbitrary_environment(monkeypatch):
    monkeypatch.setenv("NETADMIN_BUILD_VERSION", "private diagnostic /secret/file")
    assert version() == "unknown"


def test_deployment_tag_does_not_override_build_identity(monkeypatch):
    monkeypatch.setenv("NETADMIN_VERSION", "2026.11.99")
    monkeypatch.setenv("NETADMIN_BUILD_VERSION", "2026.11.2")
    assert version() == "2026.11.2"
    monkeypatch.delenv("NETADMIN_BUILD_VERSION")
    assert version() == "unknown"


def test_build_metadata_is_wired_to_images_and_publication():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    files = ["Dockerfile"] + [
        f"docker/Dockerfile.{name}"
        for name in ("dhcp-agent", "dns-agent", "radius-agent", "ca-agent", "ca-runtime")
    ]
    for filename in files:
        content = (root / filename).read_text()
        assert "ARG NETADMIN_BUILD_VERSION=unknown" in content
        assert "ENV NETADMIN_BUILD_VERSION=${NETADMIN_BUILD_VERSION}" in content
        assert "ENV NETADMIN_VERSION=" not in content
    assert (
        "ENV NETADMIN_BUILD_VERSION=${BUILD_VERSION}"
        in (root / "home-assistant/netadmin/Dockerfile").read_text()
    )
    assert (
        '--build-arg "NETADMIN_BUILD_VERSION=$PUBLISH_VERSION"'
        in (root / ".github/workflows/publish.yml").read_text()
    )


@pytest.mark.parametrize(
    "authorities",
    [
        [],
        [{"id": "imported", "managed": False, "endpoint": "https://ca"}],
        [{"id": "incomplete", "managed": True, "endpoint": ""}],
    ],
)
def test_no_configured_managed_issuer_is_unready(runtime, monkeypatch, authorities):  # noqa: F811
    app, client, headers = runtime
    monkeypatch.setattr(app.extensions["ca_store"], "status", lambda: {"authorities": authorities})
    response = client.get("/ready", headers=headers)
    assert response.status_code == 503
    assert response.json["ready"] is False


@pytest.mark.parametrize("exit_code,expected", [(None, 200), (1, 503)])
def test_configured_issuer_readiness_tracks_process(runtime, monkeypatch, exit_code, expected):  # noqa: F811
    from types import SimpleNamespace

    app, client, headers = runtime
    monkeypatch.setattr(
        app.extensions["ca_store"],
        "status",
        lambda: {
            "authorities": [{"id": "issuer", "managed": True, "endpoint": "https://issuer"}],
        },
    )
    app.extensions["ca_issuers"].processes["issuer"] = SimpleNamespace(poll=lambda: exit_code)
    response = client.get("/ready", headers=headers)
    assert response.status_code == expected
    assert response.json["ready"] is (exit_code is None)


@pytest.mark.parametrize("kind", ["dns", "dhcp"])
def test_native_readiness_timeout_is_redacted(monkeypatch, kind):
    def failure(command, **kwargs):
        assert kwargs["timeout"] == 5
        raise subprocess.TimeoutExpired(command, 5, stderr="private diagnostic")

    monkeypatch.setattr("netadmin.health.subprocess.run", failure)
    assert not ready(kind)


def test_legacy_agent_metadata_is_unknown_not_matching(monkeypatch):
    agent = AgentClient("https://agent.test", "synthetic")

    def get(_path, **_kwargs):
        response = httpx.Response(404, request=httpx.Request("GET", "https://agent.test/ready"))
        response.raise_for_status()

    monkeypatch.setattr(agent, "get", get)
    assert agent.deployment_info() == ("unknown", None)


def test_failed_readiness_keeps_safe_metadata(monkeypatch):
    agent = AgentClient("https://agent.test", "synthetic")

    def get(_path, **_kwargs):
        assert _kwargs["timeout"] == 8
        response = httpx.Response(
            503,
            json={"version": "2026.11.2", "ready": False},
            request=httpx.Request("GET", "https://agent.test/ready"),
        )
        response.raise_for_status()

    monkeypatch.setattr(agent, "get", get)
    assert agent.deployment_info() == ("2026.11.2", False)


def test_private_runtime_readiness_requires_management_scope(runtime):  # noqa: F811
    _app, client, headers = runtime
    assert client.get("/ready").status_code == 403
    response = client.get("/ready", headers=headers)
    assert response.status_code == 503
    assert response.json["ready"] is False


@pytest.mark.parametrize("kind", ["dns", "dhcp", "kea"])
def test_native_readiness_success_is_read_only(monkeypatch, kind):
    calls = []
    monkeypatch.setenv("DHCP_SERVER", "kea" if kind == "kea" else "isc")
    monkeypatch.setattr(
        "netadmin.health.subprocess.run", lambda command, **kwargs: calls.append((command, kwargs))
    )
    assert ready("dhcp" if kind == "kea" else kind)
    assert calls[0][1]["check"] is True
    assert "-t" in calls[0][0] or "named-checkconf" in calls[0][0][0]


def test_radius_and_legacy_ca_required_files(tmp_path, monkeypatch):
    file = tmp_path / "public.pem"
    file.touch()
    for key in ("RADIUS_AUTHORIZE_FILE", "RADIUS_CLIENTS_FILE", "STEP_CA_ROOT"):
        monkeypatch.setenv(key, str(file))
    monkeypatch.delenv("CA_CONTROL_SOCKET", raising=False)
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path))
    assert ready("radius")
    assert ready("ca")
    file.unlink()
    assert not ready("radius")
    assert not ready("ca")
    assert not ready("invalid")


def test_managed_ca_checks_private_ready_api(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    token = tmp_path / "token"
    token.write_text("synthetic-only")
    monkeypatch.setenv("CA_CONTROL_SOCKET", "/control/ca.sock")
    monkeypatch.setenv("CA_MANAGEMENT_TOKEN_FILE", str(token))
    response = SimpleNamespace(status_code=200, json=lambda: {"ready": True})
    client = SimpleNamespace(get=lambda url, **kwargs: response)
    monkeypatch.setattr("netadmin.health.httpx.Client", lambda **kwargs: nullcontext(client))
    assert ready("ca")
    response.status_code = 503
    assert not ready("ca")


@pytest.mark.parametrize("available", [True, False])
def test_probe_requires_ready_and_running_listener(monkeypatch, available):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from netadmin.health import main

    monkeypatch.setattr("sys.argv", ["health", "--kind", "dns", "--port", "8083"])
    monkeypatch.setattr("netadmin.health.ready", lambda _kind: True)
    monkeypatch.setenv("AGENT_BIND_ADDRESS", "0.0.0.0")  # noqa: S104 - test a connect-only override

    def connect(address, **kwargs):
        assert address == ("127.0.0.1", 8083)
        assert kwargs["timeout"] == 3
        if not available:
            raise OSError("unavailable")
        return nullcontext(SimpleNamespace(fileno=lambda: 1))

    monkeypatch.setattr("netadmin.health.socket.create_connection", connect)
    with pytest.raises(SystemExit) as exit_code:
        main()
    assert exit_code.value.code == (0 if available else 1)


def test_probe_rejects_arbitrary_cli_ports_before_connecting(monkeypatch):
    from netadmin.health import main

    monkeypatch.setattr("sys.argv", ["health", "--kind", "dns", "--port", "2375"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_dead_managed_issuer_is_not_ready(runtime, monkeypatch):  # noqa: F811
    app, client, headers = runtime
    monkeypatch.setattr(
        app.extensions["ca_store"],
        "status",
        lambda: {"authorities": [{"id": "missing", "managed": True, "endpoint": "https://issuer"}]},
    )
    assert client.get("/ready", headers=headers).status_code == 503
