"""Draft versions, readiness and upload retries cannot bypass publication gates."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from netadmin import release_metadata as release


@pytest.fixture
def metadata_files(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "CHECKOUT_ROOT", tmp_path)
    config = tmp_path / "home-assistant/netadmin/config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text('version: "2026.11.3"\n')
    policy = tmp_path / ".github/release-policy.json"
    policy.parent.mkdir()
    policy.write_text(json.dumps({"state_schema": 1, "image_rollback_safe": False}))
    return config, policy


def test_metadata_uses_addon_version_and_explicit_state_policy(metadata_files):
    assert release.metadata(*metadata_files) == {
        "version": "2026.11.3",
        "state_schema": 1,
        "image_rollback_safe": False,
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"state_schema": True, "image_rollback_safe": False},
        {"state_schema": 1, "image_rollback_safe": "true"},
        {},
    ],
)
def test_invalid_state_policy_is_rejected(metadata_files, bad):
    config, policy = metadata_files
    policy.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        release.metadata(config, policy)


def test_invalid_addon_version_is_rejected(metadata_files):
    config, _policy = metadata_files
    config.write_text('version: "unexpected/path"\n')
    with pytest.raises(ValueError):
        release.metadata(*metadata_files)


def test_cli_cannot_select_unrelated_metadata_files(metadata_files, tmp_path):
    _config, policy = metadata_files
    with pytest.raises(ValueError, match="fixed inputs"):
        release.metadata(tmp_path / "unrelated-private-file", policy)


def test_publication_is_not_ready_until_final_asset_set():
    data = {"draft": False, "assets": []}
    assert release.publication_state(data) == "published-not-ready"
    data["assets"] = [{"name": n, "state": "uploaded", "size": 1} for n in release.ASSETS]
    assert release.publication_state(data) == "ready"
    data["body"] = "<!--netadmin-publication:start-->\n## Publication status: failed"
    assert release.publication_state(data) == "publication-failed"
    data["draft"] = True
    assert release.publication_state(data) == "draft"


@pytest.mark.parametrize("draft", [False, True])
def test_already_published_version_is_not_redrafted(monkeypatch, draft):
    monkeypatch.setattr(
        release,
        "_gh",
        lambda *args: SimpleNamespace(returncode=0, stdout=json.dumps({"draft": draft})),
    )
    assert release.needs_draft("2026.11.2") is draft


def test_api_outage_is_not_assumed_to_mean_unpublished(monkeypatch):
    monkeypatch.setattr(
        release, "_gh", lambda *args: SimpleNamespace(returncode=1, stderr="HTTP 502")
    )
    with pytest.raises(RuntimeError):
        release.needs_draft("2026.11.3")
    monkeypatch.setattr(
        release, "_gh", lambda *args: SimpleNamespace(returncode=1, stderr="HTTP 404")
    )
    assert release.needs_draft("2026.11.3")


def test_publication_note_only_updates_body(monkeypatch):
    calls = []

    def gh(arguments, body=None):
        calls.append((arguments, body))
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"id": 1, "tag_name": "v2026.11.3", "draft": False, "body": "Retained changelog"}
            ),
        )

    monkeypatch.setattr(release, "_gh", gh)
    release.update_status("v2026.11.3", "ready")
    payload = json.loads(calls[-1][1])
    assert set(payload) == {"body"}
    assert "Retained changelog" in payload["body"]
    assert "Publication status: ready" in payload["body"]


def test_metadata_cli_emits_only_public_outputs(metadata_files, tmp_path, monkeypatch, capsys):
    config, policy = metadata_files
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(
        "sys.argv", ["metadata", "metadata", "--config", str(config), "--policy", str(policy)]
    )
    release.main()
    assert "version=2026.11.3" in capsys.readouterr().out
    assert "image_rollback_safe=false" in output.read_text()


@pytest.mark.parametrize("mode,count", [("transient", 2), ("permanent", 1), ("exhausted", 3)])
def test_registry_push_retries_only_transient_errors(tmp_path, mode, count):
    executable = tmp_path / "docker"
    executable.write_text(
        "#!/usr/bin/env python3\nimport os,pathlib,sys\n"
        "p=pathlib.Path(os.environ['CALLS'])\n"
        "n=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\n"
        "mode=os.environ['MODE']\n"
        "if mode=='permanent': print('denied private-token'); sys.exit(1)\n"
        "if mode=='exhausted' or n==1: print('unknown blob'); sys.exit(1)\nsys.exit(0)\n"
    )
    executable.chmod(0o700)
    sleep = tmp_path / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o700)
    calls = tmp_path / "calls"
    environment = os.environ | {
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "CALLS": str(calls),
        "MODE": mode,
    }
    script = Path(__file__).resolve().parents[1] / "Tools/push_image.sh"
    result = subprocess.run(  # noqa: S603 - trusted local script and synthetic test PATH
        ["/bin/bash", str(script), "ghcr.io/timlaing/netadmin:test"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert int(calls.read_text()) == count
    assert result.returncode == (0 if mode == "transient" else 1)
    assert "private-token" not in result.stderr


@pytest.mark.parametrize("failure", [False, True])
def test_admin_publication_status_and_safe_network_failure(tmp_path, monkeypatch, failure):
    from contextlib import nullcontext

    import httpx

    from tests.test_multi_service_ui import admin_client

    app, client = admin_client(tmp_path)
    calls = []

    def get(_url):
        calls.append("get")
        if failure:
            raise httpx.ReadTimeout("synthetic-private-diagnostic")
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "tag_name": "v2026.11.3",
                "assets": [{"name": n, "state": "uploaded", "size": 1} for n in release.ASSETS],
            },
        )

    monkeypatch.setattr(
        "netadmin.release_web.httpx.Client", lambda **kwargs: nullcontext(SimpleNamespace(get=get))
    )
    response = client.get("/releases/status")
    assert response.status_code == (503 if failure else 200)
    assert "synthetic-private-diagnostic" not in response.text
    assert response.json["state"] == ("unknown" if failure else "ready")
    anonymous = app.test_client()
    assert anonymous.get("/releases/status").status_code == 302
    assert len(calls) == 1


def test_publication_workflow_promotes_only_after_readiness():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/publish.yml").read_text())
    assert "publish-installer" in workflow["jobs"]["promote-latest"]["needs"]
    assert "verify-public-images" in workflow["jobs"]["promote-latest"]["needs"]
    assert "publish-addon" in workflow["jobs"]["verify-public-images"]["needs"]
    manifest_steps = str(workflow["jobs"]["manifests"]["steps"])
    assert ":latest" not in manifest_steps
