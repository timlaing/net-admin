"""Release-aware, host-only cohort updates with encrypted checkpoints and health gates."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess  # nosec B404
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from netadmin.operations import backup, paths

REPOSITORY = "timlaing/net-admin"
IMAGE_PREFIX = "ghcr.io/timlaing/netadmin"
STABLE_VERSION = r"\d+\.\d+\.\d+"


def command(arguments: list[str], directory: Path | None = None) -> str:
    """Never echo daemon output: startup diagnostics can contain key material."""
    result = subprocess.run(  # noqa: S603 - fixed Docker executable; validated project/service args
        arguments, cwd=directory, capture_output=True, text=True, timeout=600, check=False
    )
    if result.returncode:
        raise RuntimeError("Deployment command failed; inspect private operator logs")
    return result.stdout


def release(client: httpx.Client, requested: str | None) -> dict[str, Any]:
    """Require published assets and the final readiness marker before pulling images."""
    if requested and not re.fullmatch(STABLE_VERSION, requested):
        raise ValueError("Use a stable release version")
    suffix = f"tags/v{requested}" if requested else "latest"
    response = client.get(f"https://api.github.com/repos/{REPOSITORY}/releases/{suffix}")
    response.raise_for_status()
    metadata = response.json()
    version = str(metadata.get("tag_name", "")).removeprefix("v")
    if (
        metadata.get("draft")
        or metadata.get("prerelease")
        or not re.fullmatch(STABLE_VERSION, version)
    ):
        raise ValueError("Release is not a published stable version")
    assets = {a["name"]: a for a in metadata.get("assets", []) if a.get("state") == "uploaded"}
    if (
        not {"installer-ready.json", "install.sh", "install.sh.sha256", "compose.yml"}
        <= assets.keys()
    ):
        raise ValueError("Publication is incomplete; wait for the installer readiness marker")
    asset = assets["installer-ready.json"]
    url = asset["browser_download_url"]
    if (
        asset.get("size", 0) > 4096
        or urlsplit(url).hostname != "github.com"
        or not url.startswith(f"https://github.com/{REPOSITORY}/releases/download/v{version}/")
    ):
        raise ValueError("Invalid release readiness asset")
    response = client.get(url)
    response.raise_for_status()
    if len(response.content) > 4096:
        raise ValueError("Readiness marker exceeds its limit")
    marker = response.json()
    if (
        marker.get("schema") != 1
        or marker.get("version") != version
        or not re.fullmatch(r"[0-9a-f]{40}", str(marker.get("commit", "")))
    ):
        raise ValueError("Readiness marker does not identify the release")
    return {"version": version, "commit": marker["commit"], "marker": marker}


@dataclass
class Project:
    """Explicit Compose scope; no arbitrary shell hooks or web-triggered writes."""

    directory: Path
    file: str
    name: str
    services: list[str]

    @property
    def override(self) -> Path:
        """The only additional Compose file this tool owns."""
        return self.directory / "netadmin-release.override.json"

    def compose(self, *args: str, override: bool = True) -> str:
        """Run Compose only for the declared services, with the managed override."""
        files = ["-f", self.file]
        if override and self.override.exists():
            files.extend(["-f", self.override.name])
        return command(
            ["docker", "compose", "-p", self.name, *files, *args, *self.services], self.directory
        )


def projects(plan: dict[str, Any]) -> list[Project]:
    """Validate unique scopes beneath the explicitly configured deployment root."""
    root = paths.exact(Path(plan["root"]), "NETADMIN_OPERATIONS_ROOT").resolve(strict=True)
    result = []
    for spec in plan["projects"]:
        directory = paths.existing(root, spec["directory"])
        if not directory.is_relative_to(root):
            raise ValueError("Compose directory is outside the deployment root")
        file = str(paths.existing(directory, spec["file"]).relative_to(directory))
        name = str(spec["project"])
        services = spec["services"]
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]+", name)
            or not services
            or not all(isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9_-]+", s) for s in services)
        ):
            raise ValueError("Invalid Compose project/service selection")
        if (directory / file).resolve().is_relative_to(root) is False:
            raise ValueError("Compose file escaped the deployment root")
        project = Project(directory, file, name, services)
        if (
            project.override.exists()
            and json.loads(project.override.read_text(encoding="utf-8")).get("x-netadmin-managed")
            is not True
        ):
            raise ValueError("Refusing to replace an unknown override file")
        result.append(project)
    if not result or len({p.override for p in result}) != len(result):
        raise ValueError("Select unique, nonempty Compose projects")
    return result


def _image(repository: str, version: str) -> dict[str, Any]:
    reference = f"{repository}:{version}"
    command(["docker", "pull", reference])
    image: dict[str, Any] = json.loads(command(["docker", "image", "inspect", reference]))[0]
    return image


def _update_owned(labels: dict[str, str]) -> bool:
    return (
        labels.get("wud.trigger.docker.enabled") == "false"
        and labels.get("wud.trigger.dockercompose.enabled") == "false"
        and not any(
            v == "true"
            for k, v in labels.items()
            if k.startswith(("wud.trigger.docker.", "wud.trigger.dockercompose."))
            and k.endswith(".enabled")
        )
    )


def _baseline(
    current: dict[str, Any], target: dict[str, Any], adopt: bool
) -> tuple[str, dict[str, Any]]:
    if (
        not current["State"]["Running"]
        or current["State"].get("Health", {}).get("Status") == "unhealthy"
    ):
        raise ValueError("Baseline cohort is not healthy; diagnose it before updating")
    if not adopt and not _update_owned(current["Config"].get("Labels", {})):
        raise ValueError("Pause external updaters and explicitly --adopt the cohort once")
    repository = current["Config"]["Image"].split("@", 1)[0].rsplit(":", 1)[0]
    if not repository.startswith(IMAGE_PREFIX):
        raise ValueError("Only NetAdmin release images may enter the cohort")
    prior: dict[str, Any] = json.loads(command(["docker", "image", "inspect", current["Image"]]))[0]
    version = prior["Config"].get("Labels", {}).get("org.opencontainers.image.version", "")
    if not re.fullmatch(STABLE_VERSION, version) or tuple(map(int, version.split("."))) > tuple(
        map(int, target["version"].split("."))
    ):
        raise ValueError("Unknown baseline version or attempted downgrade")
    return repository, prior


def _candidate(repository: str, target: dict[str, Any]) -> dict[str, Any]:
    image = _image(repository, target["version"])
    metadata = image["Config"].get("Labels", {})
    if (
        metadata.get("org.opencontainers.image.version") != target["version"]
        or metadata.get("org.opencontainers.image.revision") != target["commit"]
    ):
        raise ValueError("Image does not match the complete release")
    test = image["Config"].get("Healthcheck", {}).get("Test")
    if not test or test == ["NONE"]:
        raise ValueError("Cohort images must have health checks")
    return image


def _member(
    current: dict[str, Any], target: dict[str, Any], adopt: bool
) -> tuple[str, str, bool, bool]:
    repository, prior = _baseline(current, target, adopt)
    image = _candidate(repository, target)
    metadata = prior["Config"].get("Labels", {})
    same = (
        metadata.get("org.opencontainers.image.version") == target["version"]
        and metadata.get("org.opencontainers.image.revision") == target["commit"]
    )
    compatible = metadata.get("org.netadmin.state-schema") == str(
        target["marker"].get("state_schema")
    )
    return _digest(prior, repository), _digest(image, repository), same, compatible


def prepare(
    scopes: list[Project], target: dict[str, Any], *, adopt: bool
) -> tuple[list[dict[str, str]], list[dict[str, str]], set[str], bool, bool]:
    """Pull every member first; pin target and rollback refs to immutable repository digests."""
    desired, previous, identifiers = [], [], set()
    same = True
    schema_safe = bool(target["marker"].get("state_schema"))
    for scope in scopes:
        ids = scope.compose("ps", "-q").split()
        containers = json.loads(command(["docker", "inspect", *ids])) if ids else []
        by_service = {c["Config"]["Labels"]["com.docker.compose.service"]: c for c in containers}
        if set(by_service) != set(scope.services):
            raise ValueError("Every selected service must already be deployed")
        new, old = {}, {}
        for service in scope.services:
            current = by_service[service]
            identifiers.add(current["Id"])
            old[service], new[service], unchanged, compatible = _member(current, target, adopt)
            same = same and unchanged
            schema_safe = schema_safe and compatible
        desired.append(new)
        previous.append(old)
    return desired, previous, identifiers, same, schema_safe


def _digest(image: dict[str, Any], repository: str) -> str:
    for value in image.get("RepoDigests", []):
        if value.startswith(repository + "@sha256:"):
            return str(value)
    raise ValueError("An immutable rollback or release reference is unavailable")


def _exclusive_writers(root: Path, selected: set[str]) -> None:
    ids = command(["docker", "ps", "-q"]).split()
    running = json.loads(command(["docker", "inspect", *ids])) if ids else []
    for container in running:
        if container["Id"] in selected:
            continue
        if any(
            m.get("RW") and Path(m["Source"]).resolve().is_relative_to(root)
            for m in container["Mounts"]
        ):
            raise ValueError("An unselected container can write to the checkpoint root")


def _covered_mounts(plan: dict[str, Any], selected: set[str]) -> None:
    root = paths.exact(Path(plan["root"]), "NETADMIN_OPERATIONS_ROOT").resolve()
    included = [paths.existing(root, name) for name in plan["backup_includes"]]
    containers = json.loads(command(["docker", "inspect", *sorted(selected)]))
    for container in containers:
        for mount in container["Mounts"]:
            if mount.get("Type") == "tmpfs":
                continue
            source = Path(mount["Source"]).resolve()
            if not source.is_relative_to(root) or not any(
                source == p or source.is_relative_to(p) for p in included
            ):
                raise ValueError("A service mount is outside the declared backup selection")


def _write_override(scope: Project, images: dict[str, str]) -> None:
    labels = {
        "wud.trigger.docker.enabled": "false",
        "wud.trigger.dockercompose.enabled": "false",
        "wud.watch": "true",
        "wud.watch.digest": "false",
        "wud.tag.include": r"^\d+\.\d+\.\d+$",
    }
    # Also deny previously explicit per-instance labels, which outrank type defaults.
    config = json.loads(scope.compose("config", "--format", "json"))
    services = {}
    for service, image in images.items():
        deny = {
            k: "false"
            for k in config["services"][service].get("labels", {})
            if k.startswith(("wud.trigger.docker.", "wud.trigger.dockercompose."))
            and k.endswith(".enabled")
        }
        services[service] = {"image": image, "labels": labels | deny}
    path = scope.override.with_suffix(".tmp")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"x-netadmin-managed": True, "services": services}, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(path, scope.override)


def _healthy(scope: Project, images: dict[str, str]) -> None:
    ids = scope.compose("ps", "-q").split()
    containers = json.loads(command(["docker", "inspect", *ids])) if ids else []
    if len(containers) != len(images):
        raise RuntimeError("Cohort member is missing after activation")
    for container in containers:
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        if container["State"].get("Health", {}).get("Status") != "healthy" or container["Config"][
            "Image"
        ] != images.get(service):
            raise RuntimeError("Cohort member failed the immutable-image health gate")


def _resume(
    scopes: list[Project],
    previous: list[dict[str, str]],
    stopped: list[Project],
    originals: dict[Path, bytes | None],
) -> None:
    """Restore only container images/configuration, never checkpointed persistent data."""
    for path, original in originals.items():
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(original)
    for scope, images in zip(scopes, previous, strict=True):
        if scope in stopped:
            _write_override(scope, images)
            scope.compose(
                "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "120"
            )
            _healthy(scope, images)


def _journal(
    path: Path, phase: str, target: dict[str, Any], previous: list[dict[str, str]]
) -> None:
    """Retain non-secret recovery references across process interruption."""
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "phase": phase,
                "version": target["version"],
                "commit": target["commit"],
                "previous_images": previous,
            },
            handle,
        )
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _storage(plan: dict[str, Any], root: Path) -> Path:
    destination = paths.exact(Path(plan["backup_directory"]), "NETADMIN_BACKUP_DIRECTORY").resolve(
        strict=True
    )
    if destination.is_relative_to(root) or destination.stat().st_mode & 0o077:
        raise ValueError("Backup directory must be private and outside the checkpoint root")
    for journal in destination.glob("checkpoint-*.json"):
        if json.loads(journal.read_text(encoding="utf-8")).get("phase") not in {
            "complete",
            "rolled-back",
            "recovered",
        }:
            raise ValueError(
                "A prior update is incomplete; verify manual recovery before continuing"
            )
    return destination


def _original_overrides(scopes: list[Project]) -> dict[Path, bytes | None]:
    return {p.override: p.override.read_bytes() if p.override.exists() else None for p in scopes}


def apply(
    plan: dict[str, Any],
    target: dict[str, Any],
    password: bytes,
    *,
    adopt: bool = False,
    allow_image_rollback: bool = False,
) -> dict[str, str]:
    """No state rewind: failures after activation require explicit compatible image rollback."""
    scopes = projects(plan)
    desired, previous, selected, same, schema_safe = prepare(scopes, target, adopt=adopt)
    if same and not adopt:
        return {"state": "already-current", "version": target["version"]}
    root = paths.exact(Path(plan["root"]), "NETADMIN_OPERATIONS_ROOT").resolve()
    _exclusive_writers(root, selected)
    _covered_mounts(plan, selected)
    destination = _storage(plan, root)
    old_overrides = _original_overrides(scopes)
    activated = False
    stopped: list[Project] = []
    archive = destination / f"checkpoint-{target['version']}-{os.urandom(6).hex()}.enc"
    journal = archive.with_suffix(".json")
    _journal(journal, "prepared", target, previous)
    try:
        for scope in reversed(scopes):
            stopped.append(scope)
            scope.compose("stop")
        backup.create(root, plan["backup_includes"], archive, password, quiesced=True)
        _journal(journal, "checkpointed", target, previous)
        # A cryptographic verify is not enough: rehearse file restoration before activation.
        rehearsal = destination / (archive.stem + "-restore-test")
        backup.restore(archive, password, rehearsal)
        _journal(journal, "activating", target, previous)
        for scope, images in zip(scopes, desired, strict=True):
            _write_override(scope, images)
            activated = True
            scope.compose(
                "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "120"
            )
            _healthy(scope, images)
    except Exception:
        _journal(journal, "recovery-required", target, previous)
        if activated:
            for scope in reversed(scopes):
                scope.compose("stop")
        compatible = (
            allow_image_rollback
            and schema_safe
            and target["marker"].get("image_rollback_safe") is True
        )
        if not activated or compatible:
            _resume(scopes, previous, stopped, old_overrides)
            _journal(journal, "rolled-back", target, previous)
        raise RuntimeError(
            "Update failed; checkpoint retained. Inspect state before manual recovery."
        ) from None
    _journal(journal, "complete", target, previous)
    return {"state": "updated", "version": target["version"], "checkpoint": archive.name}


def main() -> None:
    """An opt-in timer-friendly host CLI, not a web API and not an automatic migration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--version")
    parser.add_argument("--adopt", action="store_true")
    parser.add_argument("--allow-image-rollback", action="store_true")
    args = parser.parse_args()
    try:
        plan_file = paths.exact(args.plan, "NETADMIN_UPDATE_PLAN")
        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        destination = paths.configured("NETADMIN_BACKUP_DIRECTORY").resolve(strict=True)
        with ExitStack() as stack:
            descriptor = os.open(
                destination / ".update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
            )
            stack.callback(os.close, descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                target = release(client, args.version)
            result = apply(
                plan,
                target,
                backup.password_file(args.password_file),
                adopt=args.adopt,
                allow_image_rollback=args.allow_image_rollback,
            )
            print(json.dumps(result))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        httpx.HTTPError,
        subprocess.SubprocessError,
    ):
        parser.exit(
            1, "Cohort update failed; use the private checkpoint and operator diagnostics.\n"
        )


if __name__ == "__main__":
    main()
