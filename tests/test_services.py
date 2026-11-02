"""Tests for external service adapters."""

from pathlib import Path
from types import SimpleNamespace

import httpx

from netadmin.auth import authenticate_radius
from netadmin.config import Settings
from netadmin.services.agents import AgentClient


def test_radius_role_mapping(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        return SimpleNamespace(returncode=0, stdout='Access-Accept\nFilter-Id = "admin-value"')

    monkeypatch.setattr("netadmin.auth.subprocess.run", fake_run)
    settings = Settings(
        secret_key="x",  # noqa: S106
        root_password_hash="x",  # noqa: S106
        data_dir=tmp_path,
        radius_secret="shared-secret",  # noqa: S106
        radius_admin_value="admin-value",
    )
    assert authenticate_radius("alice", "password", settings) == "admin"


def test_radius_reject(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "netadmin.auth.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="Access-Reject"),
    )
    settings = Settings(
        secret_key="x",  # noqa: S106
        root_password_hash="x",  # noqa: S106
        data_dir=tmp_path,
        radius_secret="shared-secret",  # noqa: S106
    )
    assert authenticate_radius("alice", "bad", settings) is None


def test_agent_client(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self):  # type: ignore[no-untyped-def]
            return {"ok": True}

    class Client:
        def __init__(self, **kwargs):  # type: ignore[no-untyped-def]
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args):  # type: ignore[no-untyped-def]
            return None

        def get(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return Response()

        def post(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return Response()

    monkeypatch.setattr(httpx, "Client", Client)
    client = AgentClient("https://agent", "token")
    assert client.get("health") == {"ok": True}
    assert client.post("items", {"name": "one"}) == {"ok": True}


def test_agent_client_uses_mtls(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    captured = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self):  # type: ignore[no-untyped-def]
            return []

    class Client:
        def __init__(self, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args):  # type: ignore[no-untyped-def]
            return None

        def get(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return Response()

    monkeypatch.setattr(httpx, "Client", Client)
    tls = SimpleNamespace(load_cert_chain=lambda *paths: captured.update(client_chain=paths))
    monkeypatch.setattr(
        "netadmin.services.agents.ssl.create_default_context",
        lambda **kwargs: captured.update(context_options=kwargs) or tls,
    )
    client = AgentClient(
        "https://agent", "token", tmp_path / "ca", tmp_path / "cert", tmp_path / "key"
    )
    client.get("health")
    assert captured["verify"] is tls
    assert captured["context_options"] == {"cafile": str(tmp_path / "ca")}
    assert captured["client_chain"] == (str(tmp_path / "cert"), str(tmp_path / "key"))
    assert "cert" not in captured
