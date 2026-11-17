"""Repeated failures, interrupted journals and state-schema limits remain fail-closed."""

import errno
import json
import os

import pytest

from netadmin.agents.common import ConfigurationChanged, validated_transaction
from netadmin.operations import update
from tests.test_coordinated_updates import PASSWORD, TARGET, deployment  # noqa: F401


def test_candidate_wrapper_failure_closes_descriptor_and_removes_staged_file(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text("original")
    descriptors = []

    def fail(descriptor, *_args, **_kwargs):
        descriptors.append(descriptor)
        raise OSError("synthetic wrapper failure")

    monkeypatch.setattr("netadmin.agents.common.os.fdopen", fail)
    with pytest.raises(OSError):
        validated_transaction({path: "candidate"}, lambda: None, [], allowed_roots=(tmp_path,))
    assert path.read_text() == "original"
    assert list(tmp_path.iterdir()) == [path]
    with pytest.raises(OSError) as error:
        os.fstat(descriptors[0])
    assert error.value.errno == errno.EBADF


def test_native_edit_between_review_and_staging_never_reloads(tmp_path):
    path = tmp_path / "config"
    path.write_text("native edit")

    def unexpected_validation():
        pytest.fail("Changed snapshots must fail before validation/reload")

    with pytest.raises(ConfigurationChanged):
        validated_transaction(
            {path: "candidate"},
            unexpected_validation,
            [],
            allowed_roots=(tmp_path,),
            expected_originals={path: b"reviewed original"},
        )
    assert path.read_text() == "native edit"


def test_incomplete_previous_operation_blocks_automatic_retry(deployment):  # noqa: F811
    plan, calls, _failures, directory = deployment
    journal = directory / "checkpoint-interrupted.json"
    journal.write_text(json.dumps({"phase": "activating"}))
    with pytest.raises(ValueError, match="prior update"):
        update.apply(plan, TARGET, PASSWORD)
    assert not any("stop" in args for args in calls)


def test_unknown_state_schema_cannot_enable_image_rollback(deployment):  # noqa: F811
    plan, calls, failures, _directory = deployment
    failures.add("health")
    target = TARGET | {"marker": {"image_rollback_safe": True}}
    with pytest.raises(RuntimeError):
        update.apply(plan, target, PASSWORD, allow_image_rollback=True)
    assert len([a for a in calls if "up" in a]) == 1


def test_restore_rehearsal_failure_prevents_activation(deployment, monkeypatch):  # noqa: F811
    plan, calls, _failures, directory = deployment

    def failure(*_args, **_kwargs):
        raise ValueError("synthetic rehearsal failure")

    monkeypatch.setattr(update.backup, "restore", failure)
    with pytest.raises(RuntimeError):
        update.apply(plan, TARGET, PASSWORD)
    assert list(directory.glob("*.enc"))
    assert all("up" not in a or "--pull" in a for a in calls)
    assert next(directory.glob("checkpoint-*.json")).read_text().find("rolled-back") >= 0


def test_health_disabled_in_compose_is_not_accepted(monkeypatch, tmp_path):
    project = update.Project(tmp_path, "compose.json", "synthetic", ["dns"])
    monkeypatch.setattr(project, "compose", lambda *_args, **_kwargs: "id")
    monkeypatch.setattr(
        update,
        "command",
        lambda *_args: json.dumps(
            [
                {
                    "Config": {"Image": "pinned", "Labels": {"com.docker.compose.service": "dns"}},
                    "State": {"Running": True},
                }
            ]
        ),
    )
    with pytest.raises(RuntimeError, match="health gate"):
        update._healthy(project, {"dns": "pinned"})  # pylint: disable=protected-access
