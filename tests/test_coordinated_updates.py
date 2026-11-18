"""Cohort publication, checkpoint and health failures never silently rewind state."""

import json
from pathlib import Path
from types import SimpleNamespace

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


def test_release_rejects_draft_or_prerelease():
    for flag in ("draft", "prerelease"):

        def handler(request, flag=flag):
            return httpx.Response(
                200,
                json={
                    "tag_name": "v2026.11.3",
                    flag: True,
                    "assets": [],
                },
            )

        with (
            httpx.Client(transport=httpx.MockTransport(handler)) as client,
            pytest.raises(ValueError, match="not a published stable version"),
        ):
            update.release(client, "2026.11.3")


def test_release_rejects_invalid_readiness_asset():
    marker_url = (
        "https://github.com/timlaing/net-admin/releases/download/v2026.11.3/installer-ready.json"
    )
    assets = [
        {"name": name, "state": "uploaded", "size": 100, "browser_download_url": marker_url}
        for name in ("installer-ready.json", "install.sh", "install.sh.sha256", "compose.yml")
    ]

    def handler(request):
        if str(request.url) == marker_url:
            return httpx.Response(
                200, json={"schema": 1, "version": "2026.11.3", "commit": "b" * 40}
            )
        return httpx.Response(
            200,
            json={
                "tag_name": "v2026.11.3",
                "draft": False,
                "prerelease": False,
                "assets": [dict(a, size=9000) for a in assets],
            },
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ValueError, match="Invalid release readiness asset"),
    ):
        update.release(client, "2026.11.3")


def test_release_rejects_oversized_marker():
    marker_url = (
        "https://github.com/timlaing/net-admin/releases/download/v2026.11.3/installer-ready.json"
    )
    assets = [
        {"name": name, "state": "uploaded", "size": 100, "browser_download_url": marker_url}
        for name in ("installer-ready.json", "install.sh", "install.sh.sha256", "compose.yml")
    ]

    def handler(request):
        if str(request.url) == marker_url:
            return httpx.Response(200, content=b"x" * 5000)
        return httpx.Response(
            200,
            json={
                "tag_name": "v2026.11.3",
                "draft": False,
                "prerelease": False,
                "assets": assets,
            },
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ValueError, match="exceeds its limit"),
    ):
        update.release(client, "2026.11.3")


def test_release_rejects_unidentified_marker():
    marker_url = (
        "https://github.com/timlaing/net-admin/releases/download/v2026.11.3/installer-ready.json"
    )
    assets = [
        {"name": name, "state": "uploaded", "size": 100, "browser_download_url": marker_url}
        for name in ("installer-ready.json", "install.sh", "install.sh.sha256", "compose.yml")
    ]

    def handler(request):
        if str(request.url) == marker_url:
            return httpx.Response(
                200, json={"schema": 1, "version": "2026.11.3", "commit": "not-a-sha"}
            )
        return httpx.Response(
            200,
            json={
                "tag_name": "v2026.11.3",
                "draft": False,
                "prerelease": False,
                "assets": assets,
            },
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ValueError, match="does not identify the release"),
    ):
        update.release(client, "2026.11.3")


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    root.mkdir()
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(root))
    monkeypatch.setenv("NETADMIN_BACKUP_DIRECTORY", str(snapshots))
    monkeypatch.setenv("NETADMIN_RESTORE_DIRECTORY", str(snapshots))
    monkeypatch.setenv("NETADMIN_UPDATE_PLAN", str(tmp_path / "plan.json"))
    monkeypatch.setenv("NETADMIN_RECOVERY_PASSWORD_FILE", str(tmp_path / "password"))
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


def test_command_success_path_returns_stdout(monkeypatch):
    monkeypatch.setattr(
        update.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="ok"),
    )
    assert update.command(["echo", "hi"]) == "ok"


def test_projects_validates_each_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    # invalid project name / empty services
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "compose.json").write_text("{}")
    with pytest.raises(ValueError, match="Invalid Compose project/service selection"):
        update.projects(
            {
                "root": str(tmp_path),
                "projects": [
                    {
                        "directory": "proj",
                        "file": "compose.json",
                        "project": "bad name!",
                        "services": [],
                    }
                ],
            }
        )
    # unknown override file
    override = tmp_path / "proj" / "netadmin-release.override.json"
    override.write_text("{}")
    with pytest.raises(ValueError, match="Refusing to replace"):
        update.projects(
            {
                "root": str(tmp_path),
                "projects": [
                    {
                        "directory": "proj",
                        "file": "compose.json",
                        "project": "proj",
                        "services": ["dns"],
                    }
                ],
            }
        )


def test_projects_requires_unique_nonempty(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="Select unique, nonempty Compose projects"):
        update.projects({"root": str(tmp_path), "projects": []})


def test_baseline_errors(monkeypatch):
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps(
            {
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.version": "2026.11.3",
                        "org.opencontainers.image.revision": "b" * 40,
                        "org.netadmin.state-schema": "1",
                    },
                    "Healthcheck": {"Test": ["CMD", "health"]},
                },
                "RepoDigests": ["ghcr.io/timlaing/netadmin-dns@sha256:" + "b" * 64],
            }
        ),
    )
    unhealthy = {
        "State": {"Running": True, "Health": {"Status": "unhealthy"}},
        "Config": {"Image": "ghcr.io/timlaing/netadmin-dns:latest"},
        "Labels": {},
    }
    running = {
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Config": {"Image": "ghcr.io/timlaing/netadmin-dns:latest"},
        "Labels": {
            "wud.trigger.docker.enabled": "false",
            "wud.trigger.dockercompose.enabled": "false",
        },
    }
    with pytest.raises(ValueError, match="not healthy"):
        update._baseline(unhealthy, TARGET, adopt=False)
    with pytest.raises(ValueError, match="Pause external updaters"):
        update._baseline(running, TARGET, adopt=False)
    foreign = dict(running)
    foreign["Config"] = dict(running["Config"])
    foreign["Config"]["Image"] = "other.io/netadmin-dns:latest"
    with pytest.raises(ValueError, match="Only NetAdmin release images"):
        update._baseline(foreign, TARGET, adopt=True)


def test_baseline_rejects_unknown_or_downgrade(monkeypatch):
    current = {
        "Id": "dns",
        "Image": "ghcr.io/timlaing/netadmin-dns@sha256:abc",
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Config": {
            "Image": "ghcr.io/timlaing/netadmin-dns@sha256:abc",
            "Labels": {
                "wud.trigger.docker.enabled": "false",
                "wud.trigger.dockercompose.enabled": "false",
                "org.opencontainers.image.version": "2026.11.2",
                "org.opencontainers.image.revision": "a" * 40,
                "org.netadmin.state-schema": "1",
            },
        },
    }
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps(
            [
                {
                    "Config": {
                        "Labels": {
                            "org.opencontainers.image.version": "2026.11.3",
                            "org.opencontainers.image.revision": "b" * 40,
                            "org.netadmin.state-schema": "1",
                        },
                        "Healthcheck": {"Test": ["CMD", "health"]},
                    },
                    "RepoDigests": ["ghcr.io/timlaing/netadmin-dns@sha256:" + "b" * 64],
                }
            ]
        ),
    )
    # baseline version higher than target -> downgrade rejected
    older = dict(TARGET)
    older["version"] = "2026.11.1"
    older["marker"] = dict(TARGET["marker"])
    with pytest.raises(ValueError, match="Unknown baseline version or attempted downgrade"):
        update._baseline(current, older, adopt=True)


def test_candidate_requires_health_check(monkeypatch):
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps(
            [
                {
                    "Config": {
                        "Labels": {
                            "org.opencontainers.image.version": TARGET["version"],
                            "org.opencontainers.image.revision": TARGET["commit"],
                        },
                        "Healthcheck": {"Test": ["NONE"]},
                    }
                }
            ]
        ),
    )
    with pytest.raises(ValueError, match="Cohort images must have health checks"):
        update._candidate("ghcr.io/timlaing/netadmin-dns", TARGET)


def test_prepare_requires_every_service_deployed(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    (tmp_path / "dns").mkdir()
    (tmp_path / "dns" / "compose.json").write_text("{}")
    scope = update.Project(tmp_path / "dns", "compose.json", "dns", ["dns"])
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps([]),
    )
    with pytest.raises(ValueError, match="Every selected service must already be deployed"):
        update.prepare([scope], TARGET, adopt=True)


def test_digest_requires_immutable_reference():
    image = {"RepoDigests": ["other.io/x@sha256:" + "a" * 64]}
    with pytest.raises(ValueError, match="immutable rollback or release reference"):
        update._digest(image, "ghcr.io/timlaing/netadmin-dns")


def test_covered_mounts_rejects_outside_or_unincluded(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    root = tmp_path
    (root / "dns").mkdir()
    (root / "dns" / "compose.json").write_text("{}")
    plan = {
        "root": str(root),
        "projects": [
            {
                "directory": "dns",
                "file": "compose.json",
                "project": "dns",
                "services": ["dns"],
            }
        ],
        "backup_directory": str(tmp_path / "snaps"),
        "backup_includes": ["dns"],
    }
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps(
            [
                {
                    "Config": {"Labels": {"com.docker.compose.service": "dns"}},
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": str(tmp_path / "outside"),
                            "RW": True,
                        }
                    ],
                }
            ]
        ),
    )
    with pytest.raises(ValueError, match="outside the declared backup selection"):
        update._covered_mounts(plan, {root / "dns"})


def test_healthy_reports_missing_or_wrong_image(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    root = tmp_path / "deployment"
    root.mkdir()
    scope = update.Project(root / "dns", "compose.json", "dns", ["dns"])
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps([]),
    )
    with pytest.raises(RuntimeError, match="Cohort member is missing after activation"):
        update._healthy(scope, {"dns": "x"})
    monkeypatch.setattr(
        update,
        "command",
        lambda *a, **k: json.dumps(
            [
                {
                    "Config": {
                        "Labels": {"com.docker.compose.service": "dns"},
                        "Image": "wrong-image",
                    },
                    "State": {"Health": {"Status": "healthy"}},
                }
            ]
        ),
    )
    with pytest.raises(RuntimeError, match="immutable-image health gate"):
        update._healthy(scope, {"dns": "right-image"})


def test_resume_restores_removed_original(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_OPERATIONS_ROOT", str(tmp_path))
    root = tmp_path / "deployment"
    root.mkdir()
    (root / "dns").mkdir()
    scope = update.Project(root / "dns", "compose.json", "dns", ["dns"])
    gone = tmp_path / "removed.json"
    gone.write_bytes(b"old")
    calls = []

    def command(args, directory=None):
        calls.append(args)
        if args[:2] == ["docker", "compose"] and "ps" in args:
            return "dns"
        if args[:2] == ["docker", "inspect"]:
            return json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {"com.docker.compose.service": "dns"},
                            "Image": "right-image",
                        },
                        "State": {"Health": {"Status": "healthy"}},
                    }
                ]
            )
        return ""

    monkeypatch.setattr(update, "command", command)
    monkeypatch.setattr(update, "_write_override", lambda *a, **k: None)
    update._resume([scope], [{"dns": "right-image"}], [scope], {gone: None})
    assert not gone.exists()


def test_storage_rejects_inside_root_or_world_readable(tmp_path, monkeypatch):
    backup_dir = tmp_path / "snaps"
    backup_dir.mkdir()
    monkeypatch.setenv("NETADMIN_BACKUP_DIRECTORY", str(backup_dir))
    plan = {"backup_directory": str(backup_dir)}
    with pytest.raises(ValueError, match="outside the checkpoint root"):
        update._storage(plan, backup_dir)
