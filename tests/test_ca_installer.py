"""Installer prepares isolated credentials without evaluating operator input."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-ca.sh"


def test_installer_dry_run_install_and_rerun(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    docker = tools / "docker"
    docker.write_text('#!/bin/sh\nif [ "$1" = ps ]; then exit 0; fi\nexit 0\n')
    docker.chmod(0o700)
    pki = tmp_path / "pki"
    pki.mkdir()
    for name in ("server.crt", "server.key", "ca.crt"):
        (pki / name).write_text("synthetic transport fixture")
    environment = tmp_path / "agents.env"
    marker = tmp_path / "must-not-execute"
    synthetic = "$(touch " + str(marker) + ")"
    environment.write_text(
        "NETADMIN_AGENT_TOKEN='" + synthetic + "'\nOTHER_SERVICE_SECRET=never-copy\n"
    )
    target = tmp_path / "deployment"
    args = [
        "bash",
        str(SCRIPT),
        "--directory",
        str(target),
        "--pki-dir",
        str(pki),
        "--agent-env",
        str(environment),
        "--version",
        "0.0.0-test",
        "--bind",
        "127.0.0.1",
    ]
    env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
    result = subprocess.run(  # noqa: S603
        [*args, "--dry-run"], env=env, capture_output=True, text=True, check=True
    )
    assert "No keys" in result.stdout
    assert not target.exists()
    result = subprocess.run(  # noqa: S603
        args,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert not marker.exists()
    assert (target / "runtime.env").read_text() == "NETADMIN_AGENT_TOKEN='" + synthetic + "'\n"
    assert "never-copy" not in (target / "runtime.env").read_text()
    assert synthetic not in result.stdout
    token = (target / "secrets/management-token").read_text()
    assert len(token) >= 32
    assert (target / "secrets/management-token").stat().st_mode & 0o077 == 0
    assert not (target / "root.key").exists()
    again = subprocess.run(  # noqa: S603
        args,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Existing CA deployment" in again.stdout
    assert (target / "secrets/management-token").read_text() == token
