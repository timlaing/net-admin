"""Cohort publication, checkpoint and health failures never silently rewind state."""

import json
from pathlib import Path

import httpx
import pytest

from netadmin.operations import update

TARGET = {
    "version": "2026.11.3",
    "commit": "b" * 40,
    "marker": {"state_schema": 1, "image_rollback_safe": True},
}
PASSWORD = b"synthetic-recovery-password"


def test_release_requires_complete_published_assets():
    def handler(request):
        return httpx.Response(
            200, json={"draft": False, "prerelease": False, "tag_name": "v2026.11.3", "assets": []}
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ValueError, match="incomplete"),
    ):
        update.release(client, "2026.11.3")


def test_complete_release_marker_is_bound_to_version_and_commit():
    url = "https://github.com/timlaing/net-admin/releases/download/v2026.11.3/installer-ready.json"
    assets = [
        {"name": name, "state": "uploaded", "size": 100, "browser_download_url": url}
        for name in ("installer-ready.json", "install.sh", "install.sh.sha256", "compose.yml")
    ]

    def handler(request):
        if str(request.url) == url:
            return httpx.Response(
                200, json={"schema": 1, "version": "2026.11.3", "commit": "b" * 40}
            )
        return httpx.Response(
            200,
            json={"tag_name": "v2026.11.3", "draft": False, "prerelease": False, "assets": assets},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert update.release(client, None)["commit"] == "b" * 40


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    root.mkdir()
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    specs = []
    containers = []
    for service in ("dns", "ca-runtime"):
        directory = root / service
        directory.mkdir()
        (directory / "compose.json").write_text("{}")
        (directory / "state").write_bytes(b"synthetic-preserved-state")
        specs.append(
            {
                "directory": service,
                "file": "compose.json",
                "project": service,
                "services": [service],
            }
        )
        containers.append(
            {
                "Id": service,
                "Image": "old-" + service,
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "Mounts": [],
                "Config": {
                    "Image": "ghcr.io/timlaing/netadmin-" + service + ":latest",
                    "Labels": {
                        "com.docker.compose.service": service,
                        "wud.trigger.docker.enabled": "false",
                        "wud.trigger.dockercompose.enabled": "false",
                    },
                },
            }
        )
    plan = {
        "root": str(root),
        "projects": specs,
        "backup_directory": str(snapshots),
        "backup_includes": ["dns", "ca-runtime"],
    }
    calls = []
    failures = set()

    def command(args, directory=None):
        calls.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            old = args[-1].startswith("old-")
            service = args[-1][4:] if old else args[-1].split("netadmin-", 1)[1].split(":")[0]
            image = {
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.version": "2026.11.2"
                        if old
                        else TARGET["version"],
                        "org.opencontainers.image.revision": "a" * 40 if old else TARGET["commit"],
                        "org.netadmin.state-schema": "1",
                    },
                    "Healthcheck": {"Test": ["CMD", "health"]},
                },
                "RepoDigests": [
                    "ghcr.io/timlaing/netadmin-" + service + "@sha256:" + ("a" if old else "b") * 64
                ],
            }
            if "metadata" in failures and not old:
                image["Config"]["Labels"]["org.opencontainers.image.revision"] = "wrong"
            return json.dumps([image])
        if args[:2] == ["docker", "inspect"]:
            return json.dumps([c for c in containers if c["Id"] in args[2:]])
        if args[:3] == ["docker", "ps", "-q"]:
            return " ".join(c["Id"] for c in containers)
        if args[:2] == ["docker", "compose"]:
            service = directory.name
            if "ps" in args:
                return service
            if "config" in args:
                return json.dumps(
                    {
                        "services": {
                            service: {"labels": {"wud.trigger.docker.local.enabled": "true"}}
                        }
                    }
                )
            if "up" in args and "health" in failures:
                failures.remove("health")
                raise RuntimeError("synthetic unhealthy cohort")
            if "up" in args:
                override = json.loads((directory / "netadmin-release.override.json").read_text())
                current = next(c for c in containers if c["Id"] == service)
                current["Config"]["Image"] = override["services"][service]["image"]
        return ""

    monkeypatch.setattr(update, "command", command)
    return plan, calls, failures, snapshots


def test_cohort_is_checkpointed_pinned_and_health_gated(deployment):
    plan, calls, _failures, snapshots = deployment
    assert update.apply(plan, TARGET, PASSWORD)["state"] == "updated"
    assert len(list(snapshots.glob("*.enc"))) == 1
    assert len(list(snapshots.glob("*-restore-test"))) == 1
    for spec in plan["projects"]:
        scope = Path(plan["root"]) / spec["directory"]
        assert (scope / "state").read_bytes() == b"synthetic-preserved-state"
        override = json.loads((scope / "netadmin-release.override.json").read_text())
        service = override["services"][spec["services"][0]]
        assert "@sha256:" in service["image"]
        assert service["labels"]["wud.trigger.docker.local.enabled"] == "false"
    assert all("--wait" in args for args in calls if "up" in args)


def test_metadata_failure_happens_before_quiescence(deployment):
    plan, calls, failures, snapshots = deployment
    failures.add("metadata")
    with pytest.raises(ValueError, match="complete release"):
        update.apply(plan, TARGET, PASSWORD)
    assert not any("stop" in args for args in calls)
    assert not list(snapshots.iterdir())


@pytest.mark.parametrize("rollback", [False, True])
def test_activation_failure_preserves_checkpoint_and_does_not_restore_data(deployment, rollback):
    plan, calls, failures, snapshots = deployment
    failures.add("health")
    with pytest.raises(RuntimeError, match="checkpoint retained"):
        update.apply(plan, TARGET, PASSWORD, allow_image_rollback=rollback)
    assert list(snapshots.glob("*.enc"))
    starts = [a for a in calls if "up" in a]
    assert len(starts) == (3 if rollback else 1)


def test_pre_activation_backup_failure_resumes_originals(deployment, monkeypatch):
    plan, calls, _failures, _snapshots = deployment

    def failure(*_args, **_kwargs):
        raise OSError("synthetic backup failure")

    monkeypatch.setattr(update.backup, "create", failure)
    with pytest.raises(RuntimeError):
        update.apply(plan, TARGET, PASSWORD)
    assert len([a for a in calls if "up" in a]) == 2


def test_cli_uses_exclusive_lock_and_safe_output(deployment, tmp_path, monkeypatch, capsys):
    from contextlib import nullcontext

    plan, _calls, _failures, _snapshots = deployment
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    password = tmp_path / "password"
    password.write_bytes(PASSWORD)
    password.chmod(0o600)
    monkeypatch.setattr(
        "sys.argv", ["update", "--plan", str(path), "--password-file", str(password)]
    )
    monkeypatch.setattr(update.httpx, "Client", lambda **kwargs: nullcontext(None))
    monkeypatch.setattr(update, "release", lambda *_args: TARGET)
    update.main()
    assert '"state": "updated"' in capsys.readouterr().out


def test_cli_failure_is_redacted(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "update",
            "--plan",
            str(tmp_path / "private-missing"),
            "--password-file",
            str(tmp_path / "secret"),
        ],
    )
    with pytest.raises(SystemExit):
        update.main()
    assert "private-missing" not in capsys.readouterr().err


def test_real_command_adapter_never_exposes_daemon_output(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        update.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stdout="private startup key", stderr="private diagnostic"
        ),
    )
    with pytest.raises(RuntimeError) as error:
        update.command(["docker", "version"])
    assert "private" not in str(error.value).replace("private operator logs", "")


def test_requested_release_and_project_traversal_are_rejected(tmp_path):
    with httpx.Client() as client, pytest.raises(ValueError):
        update.release(client, "../main")
    with pytest.raises(ValueError):
        update.projects(
            {
                "root": str(tmp_path),
                "projects": [
                    {
                        "directory": "..",
                        "file": "compose.yml",
                        "project": "bad",
                        "services": ["dns"],
                    }
                ],
            }
        )
