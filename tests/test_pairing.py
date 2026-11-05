"""Enrollment pins host identity and cannot replace settings before validation."""

import importlib.util
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from netadmin import pairing, pairing_exchange
from netadmin.preferences import read_env_file
from tests.test_connections import client_for
from tests.test_connections import runtime as runtime

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def deployment(tmp_path):
    """Generate isolated synthetic credentials with the actual host installer."""
    spec = importlib.util.spec_from_file_location(
        "pairing_installer", ROOT / "scripts/install_services.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = tmp_path / "deployment"
    directory.mkdir()
    module.certificates(directory, "127.0.0.1", ["ca"])
    (directory / "installation.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "project": "netadmin-services",
                "address": "127.0.0.1",
                "dns": "no",
                "dhcp": "none",
                "radius": "no",
                "ca": "yes",
            }
        )
    )
    (directory / "agents.env").write_text("NETADMIN_AGENT_TOKEN=" + "a" * 48 + "\n")
    (directory / "secrets").mkdir()
    (directory / "secrets/management-token").write_text("b" * 48)
    return directory


def payload_for(directory):
    """Return only client identity material and management tokens."""
    return {
        "schema": 1,
        "services": ["ca"],
        "address": "192.0.2.10",
        "token": "a" * 48,
        "management_token": "b" * 48,
        "ca": (directory / "transport/client/ca.crt").read_text(),
        "certificate": (directory / "transport/client/client.crt").read_text(),
        "key": (directory / "transport/client/client.key").read_text(),
    }


def test_pairing_imports_private_files_and_applies(runtime, monkeypatch, deployment):
    """Import into a unique private directory without changing account settings."""
    client = client_for(runtime, monkeypatch)
    monkeypatch.setattr(pairing, "claim", lambda _code: payload_for(deployment))
    response = client.post("/settings/pair", data={"pairing_code": "synthetic"})
    assert response.status_code == 302
    settings = client.application.extensions["netadmin_settings"]
    assert settings.ca_enabled
    assert settings.ca_agent_url == "https://192.0.2.10:8084"
    assert settings.secret_key == runtime.secret_key
    assert settings.agent_key.stat().st_mode & 0o777 == 0o600
    assert settings.agent_key.parent.stat().st_mode & 0o777 == 0o700
    assert read_env_file()["NETADMIN_CA_MANAGEMENT_TOKEN"] == "b" * 48
    assert "a" * 48 not in client.get("/settings").text


@pytest.mark.parametrize(
    "role,addon,expected", [("standard", True, 403), (None, True, 302), ("admin", False, 403)]
)
def test_pairing_requires_admin_and_persistent_settings(
    runtime, monkeypatch, role, addon, expected
):
    """Reject enrollment before network access for unauthorized clients."""
    client = client_for(runtime, monkeypatch, role=role, addon=addon)
    monkeypatch.setattr(pairing, "claim", lambda _: pytest.fail("must not contact host"))
    assert client.post("/settings/pair").status_code == expected


def test_invalid_credentials_keep_active_settings(runtime, monkeypatch, deployment):
    """Never save a key which fails certificate validation."""
    client = client_for(runtime, monkeypatch)
    payload = payload_for(deployment)
    payload["key"] = (deployment / "transport/authority/ca.key").read_text()
    monkeypatch.setattr(pairing, "claim", lambda _: payload)
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 400
    assert not read_env_file()
    assert client.application.extensions["netadmin_settings"] is runtime


def test_pin_checked_before_authorization(monkeypatch, deployment):
    """Do not disclose the secret to a substituted TLS certificate."""
    monkeypatch.setattr(
        pairing_exchange.ssl,
        "get_server_certificate",
        lambda *_a, **_k: (deployment / "transport/ca/server.crt").read_text(),
    )
    monkeypatch.setattr(
        pairing_exchange.http.client,
        "HTTPSConnection",
        lambda *_a, **_k: pytest.fail("secret connection created before pin validation"),
    )
    code = "netadmin-pair://192.0.2.10:8085/" + "a" * 43 + "#" + "0" * 64
    with pytest.raises(ValueError, match="identity"):
        pairing_exchange.claim(code)


def test_real_tls_exchange_consumed_once(deployment, monkeypatch, capsys):
    """Exercise the real TLS listener and client; a consumed server closes."""
    original = pairing_exchange.parse_code
    monkeypatch.setattr(
        pairing_exchange,
        "parse_code",
        lambda code: ("127.0.0.1", *original(code.replace("127.0.0.1", "192.0.2.10"))[1:]),
    )
    thread = threading.Thread(target=pairing_exchange.serve, args=(deployment, 0, 5), daemon=True)
    thread.start()
    code = ""
    for _ in range(100):
        output = capsys.readouterr().out
        code = next(
            (line for line in output.splitlines() if line.startswith("netadmin-pair://")), ""
        )
        if code:
            break
        time.sleep(0.02)
    assert code
    bad_code = code.replace(code.split("/")[-1].split("#")[0], "z" * 43)
    with pytest.raises(ValueError, match="expired or already used"):
        pairing_exchange.claim(bad_code)
    payload = pairing_exchange.claim(code)
    thread.join(timeout=6)
    assert not thread.is_alive()
    assert payload["token"] == "a" * 48
    assert payload["key"] == (deployment / "transport/client/client.key").read_text()
    assert payload["key"] != (deployment / "transport/authority/ca.key").read_text()
    with pytest.raises(OSError):
        pairing_exchange.claim(code)


def test_pairing_preserves_csrf_protection(runtime, monkeypatch):
    """An administrator session alone cannot authorize a cross-site enrollment."""
    client = client_for(runtime, monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    monkeypatch.setattr(pairing, "claim", lambda _: pytest.fail("must not contact host"))
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 400


def test_claim_response_has_aggregate_deadline(monkeypatch):
    """Continuous data cannot reset the overall response time budget."""
    ticks = iter([0.0, 0.4, 0.8, 1.2])
    monkeypatch.setattr(pairing_exchange.time, "monotonic", lambda: next(ticks))
    response = type("SlowResponse", (), {"read1": lambda _self, _size: b"x"})()
    with pytest.raises(TimeoutError, match="deadline"):
        pairing_exchange.read_response(response, 1.0)


def test_pairing_preserves_radius_login_and_enables_administration(
    runtime, monkeypatch, deployment
):
    """Import administration independently of an existing RADIUS authentication server."""
    from dataclasses import replace

    original = replace(
        runtime,
        radius_enabled=True,
        radius_host="login.example",
        radius_secret="existing-login-secret",  # noqa: S106 - synthetic login policy
    )
    client = client_for(original, monkeypatch)
    payload = payload_for(deployment)
    payload["services"] = ["radius"]
    payload["management_token"] = ""
    monkeypatch.setattr(pairing, "claim", lambda _: payload)
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 302
    active = client.application.extensions["netadmin_settings"]
    assert active.radius_enabled
    assert active.radius_host == "login.example"
    assert active.radius_secret == original.radius_secret
    assert active.service_enabled("radius")
    assert active.radius_agent_url == "https://192.0.2.10:8082"


def test_radius_administration_works_before_login(runtime, monkeypatch, deployment):
    """A newly paired RADIUS-only host can manage clients without a login secret."""
    client = client_for(runtime, monkeypatch)
    payload = payload_for(deployment)
    payload["services"] = ["radius"]
    payload["management_token"] = ""
    monkeypatch.setattr(pairing, "claim", lambda _: payload)
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 302
    active = client.application.extensions["netadmin_settings"]
    assert not active.radius_enabled
    assert active.service_enabled("radius")
    calls = []
    monkeypatch.setattr(
        "netadmin.services.agents.AgentClient.post", lambda *_args, **_kwargs: calls.append(_args)
    )
    response = client.post(
        "/radius/clients",
        data={
            "name": "app",
            "address": "192.0.2.20",
            "shortname": "app",
            "secret": payload["token"],
        },
    )
    assert response.status_code == 302
    assert calls


def test_non_dns_pairing_clears_dormant_dns_path(runtime, monkeypatch, deployment):
    """An inactive agent-mode DNS path cannot block a CA-only enrollment."""
    from dataclasses import replace

    original = replace(
        runtime,
        dns_use_agent=True,
        dns_agent_url="https://old.example:8083",
        dns_config_path=Path("relative-unused"),
    )
    client = client_for(original, monkeypatch)
    monkeypatch.setattr(pairing, "claim", lambda _: payload_for(deployment))
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 302
    assert client.application.extensions["netadmin_settings"].dns_config_path is None


def test_committed_identity_survives_abort(runtime, monkeypatch, deployment):
    """A worker abort after env replacement must not delete its committed key files."""
    client_for(runtime, monkeypatch)
    monkeypatch.setattr(pairing, "claim", lambda _: payload_for(deployment))
    original_write = pairing.write_env_file

    def abort_after_commit(values):
        """Simulate a worker timeout immediately after the durable replacement."""
        original_write(values)
        raise SystemExit(1)

    monkeypatch.setattr(pairing, "write_env_file", abort_after_commit)
    with pytest.raises(SystemExit):
        pairing.enroll(runtime, "synthetic")
    saved = read_env_file()
    assert all(Path(saved["NETADMIN_AGENT_" + name]).is_file() for name in ("CA", "CERT", "KEY"))


def test_retired_keys_wait_for_inflight_requests(runtime, monkeypatch, deployment):
    """Delete superseded managed keys only after the last shared lease is released."""
    from netadmin.pairing_credentials import lease

    client = client_for(runtime, monkeypatch)
    monkeypatch.setattr(pairing, "claim", lambda _: payload_for(deployment))
    assert client.post("/settings/pair", data={"pairing_code": "first"}).status_code == 302
    previous = client.application.extensions["netadmin_settings"]
    old = previous.agent_key.parent
    handle = lease(previous)
    assert handle is not None
    try:
        assert client.post("/settings/pair", data={"pairing_code": "second"}).status_code == 302
        assert old.exists()
    finally:
        handle.close()
    client.get("/settings")
    assert not old.exists()
    assert client.application.extensions["netadmin_settings"].agent_key.is_file()


def test_client_key_usage_rejected_before_settings_replace(runtime, monkeypatch, deployment):
    """A correctly signed client certificate still needs an acceptable TLS KeyUsage."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    client = client_for(runtime, monkeypatch)
    payload = payload_for(deployment)
    original = x509.load_pem_x509_certificate(payload["certificate"].encode())
    authority_key = serialization.load_pem_private_key(
        (deployment / "transport/authority/ca.key").read_bytes(), password=None
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.issuer)
        .public_key(original.public_key())
        .serial_number(123456)
        .not_valid_before(original.not_valid_before_utc)
        .not_valid_after(original.not_valid_after_utc)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(False, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .sign(authority_key, hashes.SHA256())
    )
    payload["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
    monkeypatch.setattr(pairing, "claim", lambda _: payload)
    assert client.post("/settings/pair", data={"pairing_code": "synthetic"}).status_code == 400
    assert not read_env_file()


def test_listener_deadline_interrupts_partial_headers(deployment, monkeypatch, capsys):
    """A slow client cannot keep the listener alive beyond the enrollment window."""
    import socket
    import ssl

    thread = threading.Thread(target=pairing_exchange.serve, args=(deployment, 0, 1), daemon=True)
    thread.start()
    code = ""
    for _ in range(100):
        code = next(
            (
                line
                for line in capsys.readouterr().out.splitlines()
                if line.startswith("netadmin-pair://")
            ),
            "",
        )
        if code:
            break
        time.sleep(0.01)
    assert code
    port = int(code.split(":")[2].split("/")[0])
    context = ssl.create_default_context(cafile=str(deployment / "transport/client/ca.crt"))
    with (
        socket.create_connection(("127.0.0.1", port), timeout=2) as raw,
        context.wrap_socket(raw, server_hostname="127.0.0.1") as connection,
    ):
        connection.sendall(b"POST /claim HTTP/1.1\r\nX-Slow: ")
        for _ in range(15):
            try:
                connection.sendall(b"a")
            except OSError:
                break
            time.sleep(0.1)
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_resume_refuses_pairing_with_older_saved_installer(tmp_path):
    """Check saved helper capabilities before forwarding the new enrollment flag."""
    directory = tmp_path / "legacy"
    (directory / "bootstrap").mkdir(parents=True)
    helper = directory / "bootstrap/install_services.py"
    helper.write_text(
        "import argparse\np = argparse.ArgumentParser()\n"
        'p.add_argument("--resume", action="store_true")\np.parse_args()\n'
    )
    launcher = (ROOT / "scripts/install.sh").read_text()
    start = launcher.index('if [[ "$resume" == true ]]; then\n  [[ -f')
    section = launcher[start : launcher.index("# Ignore newer releases", start)]
    script = (
        'set -euo pipefail\nresume=true\npair=true\ndirectory="$1"\npython_command="$2"\n'
        'fail() { echo "$*" >&2; exit 1; }\n' + section
    )
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script, "probe", str(directory), sys.executable],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "predates pairing" in result.stderr
    assert "unrecognized arguments" not in result.stderr
