"""Release metadata/CI helpers: publishing a release is not proof of usable images."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

REPO = "timlaing/net-admin"
ASSETS = {"install.sh", "install.sh.sha256", "compose.yml", "installer-ready.json"}
CHECKOUT_ROOT = Path(__file__).resolve().parents[1]


def metadata(config: Path, policy: Path) -> dict[str, Any]:
    """Read only the add-on version and reviewed persistent-state policy."""
    expected_config = CHECKOUT_ROOT / "home-assistant/netadmin/config.yaml"
    expected_policy = CHECKOUT_ROOT / ".github/release-policy.json"
    if config.absolute() != expected_config or policy.absolute() != expected_policy:
        raise ValueError("Release metadata paths must match this checkout's fixed inputs")
    if expected_config.is_symlink() or expected_policy.is_symlink():
        raise ValueError("Release metadata inputs must not be symlinks")
    match = re.search(
        r'^version:\s*"(\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?)"\s*$',
        expected_config.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        raise ValueError("Add-on version is missing or invalid")
    result = json.loads(expected_policy.read_text(encoding="utf-8"))
    if (
        not isinstance(result.get("state_schema"), int)
        or isinstance(result.get("state_schema"), bool)
        or not 1 <= result["state_schema"] <= 10000
        or not isinstance(result.get("image_rollback_safe"), bool)
    ):
        raise ValueError("Release state policy is invalid")
    return {
        "version": match[1],
        "state_schema": result["state_schema"],
        "image_rollback_safe": result["image_rollback_safe"],
    }


def publication_state(release: dict[str, Any]) -> str:
    """Only a complete, uploaded readiness asset set establishes installer readiness."""
    if release.get("draft") is True:
        return "draft"
    if re.search(
        r"<!--netadmin-publication:start-->\s*## Publication status: failed",
        str(release.get("body", "")),
    ):
        return "publication-failed"
    assets = release.get("assets", [])
    if not isinstance(assets, list) or not all(isinstance(a, dict) for a in assets):
        raise ValueError("Unexpected release asset metadata")
    uploaded = {
        a.get("name") for a in assets if a.get("state") == "uploaded" and a.get("size", 0) > 0
    }
    return "ready" if uploaded >= ASSETS else "published-not-ready"


def _gh(arguments: list[str], body: str | None = None) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("gh")
    if executable is None:
        raise RuntimeError("GitHub CLI is required")
    # Trusted CLI and fixed API scope, no shell or token arguments.
    return subprocess.run(  # noqa: S603
        [executable, *arguments],
        input=body,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def needs_draft(version: str) -> bool:
    """Never re-draft an already published version or treat an API outage as a 404."""
    result = _gh(["api", f"repos/{REPO}/releases/tags/v{version}"])
    if result.returncode == 0:
        return json.loads(result.stdout).get("draft") is True
    if "HTTP 404" in result.stderr:
        return True
    raise RuntimeError("Could not verify publication; leave draft unchanged")


def update_status(tag: str, state: str) -> None:
    """Update only a bounded generated note; never publish, re-tag or alter assets."""
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", tag):
        raise ValueError("Invalid release tag")
    result = _gh(["api", f"repos/{REPO}/releases/tags/{tag}"])
    if result.returncode:
        raise RuntimeError("Could not read release")
    release = json.loads(result.stdout)
    if release.get("draft") or release.get("tag_name") != tag:
        raise ValueError("Release must already be published")
    body = release.get("body") or ""
    body = re.sub(
        r"<!--netadmin-publication:start-->.*?<!--netadmin-publication:end-->",
        "",
        body,
        flags=re.DOTALL,
    )
    note = {
        "ready": "Images, anonymous access and installer assets passed publication gates.",
        "failed": "Publication failed. Inspect the release workflow; "
        "do not assume images or installer assets are ready.",
        "pending": "Publication is still pending; wait for the completion marker.",
    }[state]
    body += f"\n\n<!--netadmin-publication:start-->\n## Publication status: {state}\n"
    body += f"{note}\n<!--netadmin-publication:end-->\n"
    result = _gh(
        ["api", "--method", "PATCH", f"repos/{REPO}/releases/{int(release['id'])}", "--input", "-"],
        json.dumps({"body": body}),
    )
    if result.returncode:
        raise RuntimeError("Could not update publication status")


def main() -> None:
    """CI entrypoint; output contains public versions/policy only, never credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("metadata", "draft", "status"))
    parser.add_argument("--config", type=Path, default=Path("home-assistant/netadmin/config.yaml"))
    parser.add_argument("--policy", type=Path, default=Path(".github/release-policy.json"))
    parser.add_argument("--tag")
    parser.add_argument("--state", choices=("pending", "failed", "ready"))
    args = parser.parse_args()
    if args.action == "status":
        if args.tag is None or args.state is None:
            parser.error("--tag and --state are required")
        update_status(args.tag, args.state)
        return
    result = metadata(args.config, args.policy)
    if args.action == "draft":
        result["draft"] = needs_draft(result["version"])
    output = "".join(
        f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
        for key, value in result.items()
    )
    if os.getenv("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as handle:
            handle.write(output)
    print(output, end="")


if __name__ == "__main__":
    main()
