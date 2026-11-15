"""Linux-only real Docker cohort failure smoke, using disposable stub services/state."""

import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import uuid
from pathlib import Path

from netadmin.operations import update


def main():
    if sys.platform != "linux":
        raise SystemExit("Run this isolated smoke on a Linux Docker host")
    with tempfile.TemporaryDirectory(prefix="netadmin-cohort-smoke-") as directory:
        root = Path(directory)
        deployment = root / "deployment"
        deployment.mkdir()
        snapshots = root / "snapshots"
        snapshots.mkdir(mode=0o700)
        os.environ.update(
            NETADMIN_OPERATIONS_ROOT=str(deployment),
            NETADMIN_BACKUP_DIRECTORY=str(snapshots),
            NETADMIN_RESTORE_DIRECTORY=str(snapshots),
        )
        project = "netadmin-cohort-smoke-" + uuid.uuid4().hex[:12]
        repository = "ghcr.io/timlaing/netadmin-cohort-smoke-" + project.rsplit("-", 1)[-1]
        versions = ("2099.0.1", "2099.0.2")
        revision = "b" * 40
        dockerfile = root / "Dockerfile"
        dockerfile.write_text(
            "FROM alpine:3.24\nARG VERSION\n"
            "LABEL org.opencontainers.image.version=$VERSION\n"
            f"LABEL org.opencontainers.image.revision={revision}\n"
            "LABEL org.netadmin.state-schema=1\n"
            "HEALTHCHECK --interval=1s --timeout=1s --retries=1 CMD test ! -f /state/unhealthy\n"
            'CMD ["sh", "-c", "if test -n \\"$FAIL_NEW\\"; '
            'then echo new-state > /state/value; touch /state/unhealthy; fi; sleep 600"]\n'
        )
        compose = deployment / "compose.json"
        compose.write_text(
            json.dumps(
                {
                    "services": {
                        "stub": {
                            "image": repository + ":" + versions[0],
                            "environment": {"FAIL_NEW": ""},
                            "network_mode": "none",
                            "volumes": [str(deployment / "state") + ":/state"],
                            "labels": {
                                "wud.trigger.docker.enabled": "false",
                                "wud.trigger.dockercompose.enabled": "false",
                            },
                        }
                    }
                }
            )
        )
        state = deployment / "state"
        state.mkdir()
        (state / "value").write_text("old-state")
        base = ["docker", "compose", "-p", project, "-f", str(compose)]
        run = update.command
        try:
            for version in versions:
                run(
                    [
                        "docker",
                        "build",
                        "-f",
                        str(dockerfile),
                        "--build-arg",
                        "VERSION=" + version,
                        "-t",
                        repository + ":" + version,
                        str(root),
                    ]
                )
            run([*base, "up", "-d", "--wait", "--wait-timeout", "30"])
            # Local-only smoke tags have no remote RepoDigests; supply trusted local
            # names and suppress pull only. All Compose/inspect/stop/health operations
            # still run against the real isolated Docker project.
            prior = run(
                ["docker", "compose", "-p", project, "-f", str(compose), "ps", "-q"]
            ).strip()

            def local_command(args, working=None):
                if args[:2] == ["docker", "pull"]:
                    return ""
                return run(args, working)

            update.command = local_command
            original_digest = update._digest  # pylint: disable=protected-access
            update._digest = lambda image, _repository: image["Id"]  # pylint: disable=protected-access
            data = json.loads(compose.read_text())
            data["services"]["stub"]["environment"]["FAIL_NEW"] = "yes"
            compose.write_text(json.dumps(data))
            plan = {
                "root": str(deployment),
                "projects": [
                    {
                        "directory": ".",
                        "file": "compose.json",
                        "project": project,
                        "services": ["stub"],
                    }
                ],
                "backup_directory": str(snapshots),
                "backup_includes": ["compose.json", "state"],
            }
            try:
                update.apply(
                    plan,
                    {
                        "version": versions[1],
                        "commit": revision,
                        "marker": {"state_schema": 1, "image_rollback_safe": False},
                    },
                    b"synthetic-smoke-recovery-password",
                )
                raise AssertionError("An unhealthy cohort was accepted")
            except RuntimeError:
                pass
            assert (state / "value").read_text().strip() == "new-state"
            assert list(snapshots.glob("*.enc"))
            assert run([*base, "ps", "-q"]).strip() == ""
            assert prior
            print("Real Docker health failure stopped the cohort and retained checkpoint/new state")
        finally:
            update.command = run
            if "original_digest" in locals():
                update._digest = original_digest  # pylint: disable=protected-access
            override = deployment / "netadmin-release.override.json"
            files = ["-f", str(override)] if override.exists() else []
            subprocess.run(  # noqa: S603 - uniquely owned disposable project only
                [*base, *files, "down", "--remove-orphans"],
                capture_output=True,
                check=False,
            )


if __name__ == "__main__":
    main()
