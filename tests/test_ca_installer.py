"""Installer prepares isolated credentials without evaluating operator input."""

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-ca.sh"


@pytest.fixture
def installation(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    docker = tools / "docker"
    docker.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$DOCKER_CALLS"
case "$*" in
  *" exec -T ca-runtime "*) [ "$DOCKER_FAIL" != runtime ] || exit 1 ;;
  *" exec -T ca-agent "*) [ "$DOCKER_FAIL" != agent ] || exit 1 ;;
  *" pull") [ "$DOCKER_FAIL" != pull ] || exit 1 ;;
  *" up -d --no-build") [ "$DOCKER_FAIL" != up ] || exit 1 ;;
esac
exit 0
""")
    sleep = tools / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o700)
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
    calls = tmp_path / "docker-calls"
    env = {
        **os.environ,
        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        "DOCKER_CALLS": str(calls),
    }
    return SimpleNamespace(
        args=args,
        env=env,
        target=target,
        marker=marker,
        synthetic=synthetic,
        calls=calls,
        environment=environment,
        pki=pki,
    )


def test_installer_dry_run_install_and_rerun(installation):
    state = installation
    args, env, target = state.args, state.env, state.target
    marker, synthetic = state.marker, state.synthetic
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
    commands = state.calls.read_text()
    positions = [
        commands.index(text)
        for text in (
            "config --quiet",
            " pull",
            " up -d --no-build",
            " exec -T ca-runtime",
            " exec -T ca-agent",
        )
    ]
    assert positions == sorted(positions)
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
    assert "Startup was not checked" in again.stdout
    assert (target / "secrets/management-token").read_text() == token


@pytest.mark.parametrize("mode", ["runtime", "agent", "pull", "up"])
def test_installer_failed_start_never_reports_connection_success(installation, mode):
    state = installation
    response = subprocess.run(  # noqa: S603
        state.args,
        env={**state.env, "DOCKER_FAIL": mode},
        capture_output=True,
        text=True,
        check=False,
    )
    assert response.returncode != 0
    assert "Open NetAdmin Settings" not in response.stdout
    assert (state.target / "installation.json").is_file()
    if mode in {"runtime", "agent"}:
        assert "Runtime is not ready" in response.stderr


def test_installer_dry_run_validates_address_token_and_existing_directory(installation):
    state = installation
    bad = state.args.copy()
    bad[-1] = "999.999.999.999"
    response = subprocess.run(  # noqa: S603
        [*bad, "--dry-run"],
        env=state.env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert response.returncode != 0
    assert not state.target.exists()
    state.environment.write_text("OTHER_SECRET=synthetic\n")
    response = subprocess.run(  # noqa: S603
        [*state.args, "--dry-run"],
        env=state.env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert response.returncode != 0
    assert "NETADMIN_AGENT_TOKEN is required" in response.stderr
    state.environment.write_text('NETADMIN_AGENT_TOKEN="synthetic\'apostrophe"\n')
    response = subprocess.run(  # noqa: S603
        [*state.args, "--dry-run"],
        env=state.env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert response.returncode != 0
    assert "manual Compose deployment" in response.stderr
    assert not state.target.exists()
    state.environment.write_text("NETADMIN_AGENT_TOKEN=synthetic\n")
    state.target.mkdir()
    response = subprocess.run(  # noqa: S603
        [*state.args, "--dry-run"],
        env=state.env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert response.returncode != 0
    assert "no files overwritten" in response.stderr


def test_installer_preparation_copy_failure_removes_only_new_directory(installation):
    state = installation
    # Execute the script's actual preparation block with one failing file copy.
    source = SCRIPT.read_text().split("<<'PY'\n")[2].split("\nPY", 1)[0]
    fault = (
        "import shutil\n"
        "def fail(*args): raise OSError('synthetic copy failure')\n"
        "shutil.copyfile=fail\n"
    )
    args = [
        str(state.target),
        str(state.pki),
        str(state.environment),
        "0.0.0-test",
        "127.0.0.1",
        str(SCRIPT.parents[1]),
        "false",
    ]
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", fault + source, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "synthetic copy failure" in result.stderr
    assert not state.target.exists()
    assert state.environment.is_file()
    assert (state.pki / "server.key").is_file()


def test_installer_resume_commands_preserve_paths_and_listening_scope(installation, tmp_path):
    import shlex

    state = installation
    target = tmp_path / "CA setup's directory"
    args = state.args.copy()
    args[3] = str(target)
    initial = subprocess.run(  # noqa: S603
        args, env=state.env, capture_output=True, text=True, check=True
    )
    assert "agent is listening" in initial.stdout
    assert "NetAdmin must still verify the agent TLS chain and hostname" in initial.stdout
    again = subprocess.run(  # noqa: S603
        args, env=state.env, capture_output=True, text=True, check=True
    )
    for prefix, suffix in (("Resume with: ", ["pull"]), ("Then: ", ["up", "-d", "--no-build"])):
        command = shlex.split(again.stdout.split(prefix, 1)[1].splitlines()[0])
        assert command[:4] == ["docker", "compose", "-p", "netadmin-ca"]
        assert command[command.index("--project-directory") + 1] == str(target)
        assert command[command.index("-f") + 1] == str(target / "compose.yml")
        assert command[-len(suffix) :] == suffix
