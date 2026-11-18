"""Recovery cannot depend on journal space, absent health gates or a single stop."""

import configparser
import json
import stat
from pathlib import Path

import pytest

from netadmin.operations import update
from tests.test_coordinated_updates import PASSWORD, TARGET, deployment  # noqa: F401


@pytest.fixture
def cohort(deployment):  # noqa: F811
    return deployment


def test_oneshot_update_has_no_external_whole_run_deadline():
    service = Path(__file__).resolve().parents[1] / "deployment/netadmin-update.service"
    config = configparser.ConfigParser(interpolation=None)
    config.read(service)
    assert config["Service"]["Type"] == "oneshot"
    assert config["Service"]["TimeoutStartSec"] == "infinity"


@pytest.mark.parametrize(
    "location,overlap",
    [("ancestor", True), ("equal", True), ("descendant", True), ("unrelated", False)],
)
@pytest.mark.parametrize("writable", [True, False])
def test_unselected_mount_overlap_is_checked_both_directions(
    tmp_path, monkeypatch, location, overlap, writable
):
    root = tmp_path / "deployment"
    source = {
        "ancestor": tmp_path,
        "equal": root,
        "descendant": root / "state",
        "unrelated": tmp_path / "deployment-other",
    }[location]
    container = {"Id": "unselected", "Mounts": [{"Source": str(source), "RW": writable}]}
    monkeypatch.setattr(
        update, "command", lambda args: "unselected" if args[1] == "ps" else json.dumps([container])
    )
    if writable and overlap:
        with pytest.raises(ValueError, match="unselected container"):
            update._exclusive_writers(root, set())
    else:
        update._exclusive_writers(root, set())


def test_selected_writer_remains_exempt(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    container = {"Id": "selected", "Mounts": [{"Source": str(tmp_path), "RW": True}]}
    monkeypatch.setattr(
        update, "command", lambda args: "selected" if args[1] == "ps" else json.dumps([container])
    )
    update._exclusive_writers(root, {"selected"})


def test_mount_overlap_resolves_both_path_aliases(tmp_path):
    root = tmp_path / "deployment"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    assert update._overlapping_source(root, alias)
    assert update._overlapping_source(alias, root)


@pytest.mark.parametrize("status", ["missing", "starting", "unhealthy", "stopped"])
def test_incompatible_baseline_fails_before_quiescence(cohort, monkeypatch, status):
    plan, calls, _failures, _snapshots = cohort
    command = update.command

    def inspect(args, directory=None):
        result = command(args, directory)
        if args[:2] == ["docker", "inspect"]:
            containers = json.loads(result)
            for container in containers:
                if status == "missing":
                    container["State"].pop("Health", None)
                elif status == "stopped":
                    container["State"]["Running"] = False
                else:
                    container["State"]["Health"]["Status"] = status
            return json.dumps(containers)
        return result

    monkeypatch.setattr(update, "command", inspect)
    with pytest.raises(ValueError, match="Baseline cohort"):
        update.apply(plan, TARGET, PASSWORD)
    assert not any("stop" in args for args in calls)


@pytest.mark.parametrize("phase", ["prepared", "checkpointed", "activating", "recovery-required"])
def test_incomplete_journal_blocks_already_current(cohort, monkeypatch, phase):
    plan, calls, _failures, snapshots = cohort
    (snapshots / "checkpoint-prior.json").write_text(json.dumps({"phase": phase}))

    def already_current(*_args, **_kwargs):
        pytest.fail("Incomplete journals must be checked before image preparation/no-op")

    monkeypatch.setattr(update, "prepare", already_current)
    with pytest.raises(ValueError, match="prior update is incomplete"):
        update.apply(plan, TARGET, PASSWORD)
    assert calls == []


@pytest.mark.parametrize("phase", ["complete", "rolled-back", "recovered"])
def test_complete_journal_allows_existing_noop(cohort, monkeypatch, phase):
    plan, calls, _failures, snapshots = cohort
    (snapshots / "checkpoint-prior.json").write_text(json.dumps({"phase": phase}))
    monkeypatch.setattr(update, "prepare", lambda *_args, **_kwargs: ([], [], set(), True, True))
    assert update.apply(plan, TARGET, PASSWORD)["state"] == "already-current"
    assert calls == []
    assert len(list(snapshots.iterdir())) == 1


def test_full_backup_and_journal_storage_does_not_prevent_resume(cohort, monkeypatch):
    plan, calls, _failures, snapshots = cohort
    journal = update._journal
    original = OSError("synthetic full backup filesystem")
    journal_error = OSError("synthetic private journal diagnostic")

    def backup_failure(*_args, **_kwargs):
        raise original

    def write_journal(path, phase, *args):
        if phase != "prepared":
            raise journal_error
        return journal(path, phase, *args)

    monkeypatch.setattr(update.backup, "create", backup_failure)
    monkeypatch.setattr(update, "_journal", write_journal)
    with pytest.raises(update.UpdateRecoveryError) as caught:
        update.apply(plan, TARGET, PASSWORD)
    assert len([args for args in calls if "up" in args]) == 2
    assert caught.value.original_error is original
    assert caught.value.journal_errors == [journal_error, journal_error]
    assert caught.value.resume_error is None
    assert "synthetic private" not in str(caught.value)
    assert json.loads(next(snapshots.glob("checkpoint-*.json")).read_text())["phase"] == "prepared"


@pytest.mark.parametrize("failed_project", ["ca-runtime", "dns", "both"])
def test_stop_failure_attempts_every_project_and_blocks_image_rollback(
    cohort, monkeypatch, failed_project
):
    plan, calls, failures, snapshots = cohort
    failures.add("health")
    command = update.command
    stops = {"dns": 0, "ca-runtime": 0}

    def stop(args, directory=None):
        if args[:2] == ["docker", "compose"] and "stop" in args:
            stops[directory.name] += 1
            if stops[directory.name] == 2 and failed_project in {directory.name, "both"}:
                calls.append(args)
                raise RuntimeError("synthetic private stop diagnostic")
        return command(args, directory)

    monkeypatch.setattr(update, "command", stop)
    with pytest.raises(update.UpdateRecoveryError) as caught:
        update.apply(plan, TARGET, PASSWORD, allow_image_rollback=True)
    assert stops == {"dns": 2, "ca-runtime": 2}
    assert len([args for args in calls if "up" in args]) == 1
    assert len(caught.value.stop_errors) == (2 if failed_project == "both" else 1)
    assert "synthetic private" not in str(caught.value)
    assert list(snapshots.glob("*.enc"))
    assert (
        json.loads(next(snapshots.glob("checkpoint-*.json")).read_text())["phase"]
        == "recovery-required"
    )


def test_journal_failure_still_stops_all_after_activation(cohort, monkeypatch):
    plan, calls, failures, _snapshots = cohort
    failures.add("health")
    journal = update._journal

    def write_journal(path, phase, *args):
        if phase == "recovery-required":
            raise OSError("synthetic storage failure")
        return journal(path, phase, *args)

    monkeypatch.setattr(update, "_journal", write_journal)
    with pytest.raises(update.UpdateRecoveryError) as caught:
        update.apply(plan, TARGET, PASSWORD)
    assert len([args for args in calls if "stop" in args]) == 4
    assert len(caught.value.journal_errors) == 1
    assert len([args for args in calls if "up" in args]) == 1


@pytest.mark.parametrize("failed_project", ["last-provider", "middle-provider"])
def test_three_project_stop_loop_continues_after_early_or_middle_failure(
    tmp_path, monkeypatch, failed_project
):
    scopes = [
        update.Project(tmp_path / name, "compose.json", name, [name])
        for name in ("first-provider", "middle-provider", "last-provider")
    ]
    attempted = []

    def stop(scope, *args):
        assert args == ("stop",)
        attempted.append(scope.name)
        if scope.name == failed_project:
            raise RuntimeError("synthetic stop failure")
        return ""

    monkeypatch.setattr(update.Project, "compose", stop)
    failures = update._stop_all(scopes)
    assert attempted == ["last-provider", "middle-provider", "first-provider"]
    assert list(failures) == [tmp_path / failed_project]


def test_resume_failure_is_preserved_with_primary_failure(cohort, monkeypatch):
    plan, _calls, _failures, _snapshots = cohort
    primary = OSError("synthetic primary failure")
    secondary = RuntimeError("synthetic resume failure")

    def backup_failure(*_args, **_kwargs):
        raise primary

    def resume_failure(*_args, **_kwargs):
        raise secondary

    monkeypatch.setattr(update.backup, "create", backup_failure)
    monkeypatch.setattr(update, "_resume", resume_failure)
    with pytest.raises(update.UpdateRecoveryError) as caught:
        update.apply(plan, TARGET, PASSWORD)
    assert caught.value.original_error is primary
    assert caught.value.resume_error is secondary


def test_private_recovery_details_do_not_reach_cli(cohort, tmp_path, monkeypatch, capsys):
    from contextlib import nullcontext

    plan, _calls, _failures, _snapshots = cohort
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    failure = update.UpdateRecoveryError(OSError("synthetic-private-primary"))
    failure.journal_errors.append(OSError("synthetic-private-journal"))

    def reject(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(
        "sys.argv", ["update", "--plan", str(path), "--password-file", str(tmp_path / "password")]
    )
    monkeypatch.setattr(update.httpx, "Client", lambda **_kwargs: nullcontext(None))
    monkeypatch.setattr(update, "release", lambda *_args: TARGET)
    monkeypatch.setattr(update.backup, "password_file", lambda *_args: PASSWORD)
    monkeypatch.setattr(update, "apply", reject)
    with pytest.raises(SystemExit):
        update.main()
    assert "synthetic-private" not in capsys.readouterr().err


def test_resume_directory_sync_failure_raises_so_journal_stays_recovery_required(
    tmp_path, monkeypatch
):
    """Baseline restore writes and restarts the cohort, but an un-durable directory
    entry is reported so the journal stays in recovery-required for operator review."""
    directory = tmp_path / "project"
    directory.mkdir()
    scope = update.Project(directory, "compose.json", "dns", ["dns"])
    override = scope.override
    override.write_bytes(b'{"x-netadmin-managed": true}')
    calls = []

    def compose(*_args, **_kwargs):
        calls.append(_args)
        return ""

    monkeypatch.setattr(scope, "compose", compose)
    monkeypatch.setattr(update, "_healthy", lambda *a, **k: None)

    def failing_fsync(fd):
        """Fail only directory fsyncs: the staged file syncs and replaces before the
        baseline restart, then the directory entry cannot be persisted."""
        try:
            is_directory = stat.S_ISDIR(update.os.fstat(fd).st_mode)
        except OSError:
            is_directory = False
        if is_directory:
            raise OSError("synthetic directory sync failure")

    monkeypatch.setattr(update.os, "fsync", failing_fsync)

    with pytest.raises(update.UpdateRecoveryError):
        update._resume(
            [scope],
            [{"dns": "old-image"}],
            [scope],
            {override: b'{"x-netadmin-managed": true}'},
        )

    # Recovery still wrote and restarted from the baseline override, but the
    # directory entry could not be synced, so the failure propagates.
    assert override.exists()
    assert len(calls) == 1
    assert calls[0][0] == "up"


def test_resume_preserves_service_settings_while_pin_image(tmp_path, monkeypatch):
    """Recovery pins previous images but retains each service's original
    managed-activation settings (trigger opt-outs, labels) instead of replacing
    them with image-only entries."""
    directory = tmp_path / "project"
    directory.mkdir()
    scope = update.Project(directory, "compose.json", "dns", ["dns"])
    override = scope.override
    original = (
        b'{"x-netadmin-managed": true, "services": {"dns": {"image": "old",'
        b' "labels": {"wud.trigger.docker.enabled": "false",'
        b' "wud.trigger.dockercompose.enabled": "false"}}}}'
    )
    override.write_bytes(original)
    calls = []

    def compose(*_args, **_kwargs):
        calls.append(_args)
        return ""

    monkeypatch.setattr(scope, "compose", compose)
    monkeypatch.setattr(update, "_healthy", lambda *a, **k: None)
    monkeypatch.setattr(update.os, "fsync", lambda fd: None)

    update._resume(
        [scope],
        [{"dns": "pinned-image"}],
        [scope],
        {override: original},
    )

    result = json.loads(override.read_text(encoding="utf-8"))
    assert result["services"]["dns"]["image"] == "pinned-image"
    assert result["services"]["dns"]["labels"]["wud.trigger.docker.enabled"] == "false"
    assert result["services"]["dns"]["labels"]["wud.trigger.dockercompose.enabled"] == "false"
    assert calls == [
        (
            "up",
            "-d",
            "--no-build",
            "--no-deps",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "120",
        )
    ]


def test_resume_parses_captured_bytes_instead_of_rereading_disk(tmp_path, monkeypatch):
    """A restored override the disk can no longer serve still recovers from the
    bytes captured before quiescence, keeping per-instance trigger opt-outs."""
    directory = tmp_path / "project"
    directory.mkdir()
    scope = update.Project(directory, "compose.json", "dns", ["dns"])
    override = scope.override
    captured = (
        b'{"x-netadmin-managed": true, "services": {"dns": {"labels": {"wud.trigger'
        b'.docker.enabled": "false"}}}}'
    )
    calls = []

    def compose(*_args, **_kwargs):
        calls.append(_args)
        return ""

    monkeypatch.setattr(scope, "compose", compose)
    monkeypatch.setattr(update, "_healthy", lambda *a, **k: None)
    monkeypatch.setattr(update.os, "fsync", lambda fd: None)

    update._resume(
        [scope],
        [{"dns": "pinned-image"}],
        [scope],
        {override: captured},
    )

    result = json.loads(override.read_text(encoding="utf-8"))
    assert result == {
        "x-netadmin-managed": True,
        "services": {
            "dns": {
                "image": "pinned-image",
                "labels": {"wud.trigger.docker.enabled": "false"},
            }
        },
    }


def test_resume_unparseable_captured_override_raises_rather_than_rolling_back(
    tmp_path, monkeypatch
):
    """Undecodable captured bytes are a project restore failure: UpdateRecoveryError
    propagates, the journal stays recovery-required, and no image-only override is
    published in place of the original."""
    directory = tmp_path / "project"
    directory.mkdir()
    scope = update.Project(directory, "compose.json", "dns", ["dns"])
    override = scope.override
    calls = []

    def compose(*_args, **_kwargs):
        calls.append(_args)
        return ""

    monkeypatch.setattr(scope, "compose", compose)
    monkeypatch.setattr(update, "_healthy", lambda *a, **k: None)
    monkeypatch.setattr(update.os, "fsync", lambda fd: None)

    with pytest.raises(update.UpdateRecoveryError):
        update._resume(
            [scope],
            [{"dns": "pinned-image"}],
            [scope],
            {override: b"{not valid json"},
        )

    assert override.read_bytes() == b"{not valid json"


def test_resume_preserves_top_level_settings_when_pinning_images(tmp_path, monkeypatch):
    """Recovery returns the complete original mapping with only the services
    entries replaced: unrelated top-level settings survive."""
    directory = tmp_path / "project"
    directory.mkdir()
    scope = update.Project(directory, "compose.json", "dns", ["dns"])
    override = scope.override
    captured = (
        b'{"x-netadmin-managed": true, "custom": "keep", "services": {"dns": {"image": "old"}}}'
    )
    calls = []

    def compose(*_args, **_kwargs):
        calls.append(_args)
        return ""

    monkeypatch.setattr(scope, "compose", compose)
    monkeypatch.setattr(update, "_healthy", lambda *a, **k: None)
    monkeypatch.setattr(update.os, "fsync", lambda fd: None)

    update._resume(
        [scope],
        [{"dns": "pinned-image"}],
        [scope],
        {override: captured},
    )

    result = json.loads(override.read_text(encoding="utf-8"))
    assert result == {
        "x-netadmin-managed": True,
        "custom": "keep",
        "services": {"dns": {"image": "pinned-image"}},
    }
