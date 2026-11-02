"""Regression coverage for retained-file boundaries, rotation and accounting identity."""

import ssl

import pytest

from netadmin.agents import service_logs as agent_logs
from netadmin.agents.radius import create_radius_agent
from netadmin.services import service_logs as logs
from netadmin.services.agents import AgentClient
from tests.test_multi_service_ui import admin_client
from tests.test_service_logs import detail

AUTH = {"Authorization": "Bearer synthetic"}


def test_same_second_start_is_folded_before_stop():
    records = logs.accounting_records(detail("Stop", 1000) + detail("Start", 1000))
    rows = logs.session_rows(records, 1000)
    assert len(rows) == 1
    assert rows[0]["status"] == "Ended"
    assert rows[0]["started"] == logs._utc(1000)


@pytest.mark.parametrize("start_unique,stop_unique", [(False, True), (True, False)])
def test_identifier_aliases_bridge_missing_attributes(start_unique, stop_unique):
    unique = '\tAcct-Unique-Session-Id = "unique-one"\n'
    text = detail("Start", 1000, extra=unique if start_unique else "")
    text += detail("Interim-Update", 1050, extra=unique)
    text += detail("Stop", 1100, extra=unique if stop_unique else "")
    rows = logs.session_rows(logs.accounting_records(text), 1100)
    assert len(rows) == 1
    assert rows[0]["session"] == "unique-one"
    assert rows[0]["status"] == "Ended"
    assert rows[0]["started"] == logs._utc(1000)


def test_reused_short_identifier_does_not_join_distinct_unique_sessions():
    text = (
        detail("Start", 1000, extra='\tAcct-Unique-Session-Id = "unique-one"\n')
        + detail("Stop", 1100)
        + detail("Start", 1200, extra='\tAcct-Unique-Session-Id = "unique-two"\n')
        + detail("Stop", 1300)
    )
    rows = logs.session_rows(logs.accounting_records(text), 1300)
    assert len(rows) == 2
    assert {row["session"] for row in rows} == {"unique-one", "unique-two"}
    assert all(row["status"] == "Ended" for row in rows)


@pytest.mark.parametrize("epoch", ["²", "99999999999999999999", "-1"])
def test_invalid_timestamps_cannot_replace_valid_state(epoch):
    text = detail("Start", 1000) + detail("Stop", epoch)
    rows = logs.session_rows(logs.accounting_records(text), 1100)
    assert len(rows) == 1
    assert rows[0]["status"] == "Active"
    assert rows[0]["started"] == logs._utc(1000)


def test_invalid_start_and_counters_do_not_hide_valid_update():
    text = detail("Start", "99999999999999999") + detail(
        "Interim-Update",
        1100,
        extra="\tAcct-Session-Time = 100\n\tAcct-Input-Octets = ²\n\tAcct-Output-Octets = 6\n",
    )
    rows = logs.session_rows(logs.accounting_records(text), 1100)
    assert len(rows) == 1
    assert rows[0]["started"] == logs._utc(1000)
    assert rows[0]["received"] == ""
    assert rows[0]["sent"] == "6"


def test_accounting_tail_keeps_complete_leading_record_and_drops_partial_block(
    tmp_path, monkeypatch
):
    first = detail("Start", 1000, session="first")
    second = detail("Stop", 1100, session="second")
    path = tmp_path / "detail"
    path.write_text(first + second)
    monkeypatch.setattr(logs, "MAX_BYTES", len(second.encode()))
    text, consumed = logs.tail_chunk(path, logs.MAX_BYTES + 1, accounting=True)
    assert [record["Acct-Session-Id"] for record in logs.accounting_records(text)] == ["second"]
    assert consumed <= logs.MAX_BYTES + 1
    monkeypatch.setattr(logs, "MAX_BYTES", len(second.encode()) + len(first) // 2)
    text, _ = logs.tail_chunk(path, logs.MAX_BYTES + 1, accounting=True)
    assert [record["Acct-Session-Id"] for record in logs.accounting_records(text)] == ["second"]
    assert logs.accounting_records('User-Name = "phantom"\nTimestamp = 1000\n\n') == []


def test_tail_preserves_a_complete_line_at_retained_boundary(tmp_path, monkeypatch):
    path = tmp_path / "events"
    path.write_text("older\nkept\n")
    monkeypatch.setattr(logs, "MAX_BYTES", len("kept\n"))
    assert logs.tail(path) == "kept\n"


def accounting_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_ACCOUNTING_DIR", str(tmp_path))
    nas = tmp_path / "nas"
    nas.mkdir()
    return create_radius_agent().test_client(), nas


def test_rotation_does_not_hide_other_readable_files(tmp_path, monkeypatch):
    client, nas = accounting_agent(tmp_path, monkeypatch)
    (nas / "detail-one").write_text(detail("Start", 1000))
    (nas / "detail-removed").touch()
    original = agent_logs.tail_chunk

    def rotate(path, limit, **kwargs):
        if path.name == "detail-removed":
            path.unlink(missing_ok=True)
            raise FileNotFoundError("rotated")
        return original(path, limit, **kwargs)

    monkeypatch.setattr(agent_logs, "tail_chunk", rotate)
    result = client.get("/logs/sessions", headers=AUTH).json
    assert result["status"] == "available"
    assert len(result["rows"]) == 1
    assert result["rows"][0]["user"] == "alice"


def test_stat_rotation_skips_only_missing_file(tmp_path, monkeypatch):
    client, nas = accounting_agent(tmp_path, monkeypatch)
    existing = nas / "detail-one"
    existing.write_text(detail("Start", 1000))
    monkeypatch.setattr(agent_logs, "_detail_files", lambda path: [nas / "removed", existing])
    assert client.get("/logs/sessions", headers=AUTH).json["status"] == "available"


def test_event_rotation_retries_current_path(tmp_path, monkeypatch):
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("RADIUS_AUTH_LOG_FILE", str(tmp_path / "events"))
    client = create_radius_agent().test_client()
    calls = []

    def rotate(path):
        calls.append(path)
        if len(calls) == 1:
            raise FileNotFoundError("rotating")
        return "Mon Nov  2 10:00:00 2026 : Auth: Login OK: [alice] (from client ap1 port 0)\n"

    monkeypatch.setattr(agent_logs, "tail", rotate)
    result = client.get("/logs/logins", headers=AUTH).json
    assert len(calls) == 2
    assert result["status"] == "available"
    assert result["rows"][0]["user"] == "alice"


def test_accounting_read_budget_includes_boundary_bytes(tmp_path, monkeypatch):
    client, nas = accounting_agent(tmp_path, monkeypatch)
    for index in range(5):
        (nas / f"detail-{index}").touch()
    limits = []
    consumed = []

    def read(path, limit, **kwargs):
        limits.append(limit)
        used = min(2, limit)
        consumed.append(used)
        return "", used

    monkeypatch.setattr(agent_logs, "ACCOUNTING_BUDGET", 5)
    monkeypatch.setattr(agent_logs, "tail_chunk", read)
    assert client.get("/logs/sessions", headers=AUTH).json["status"] == "available"
    assert limits == [5, 3, 1]
    assert sum(consumed) == 5


def test_directory_retention_limit_has_distinct_guidance(tmp_path, monkeypatch):
    client, _ = accounting_agent(tmp_path, monkeypatch)

    def too_many(path):
        raise agent_logs.RetentionLimit("synthetic private directory")

    monkeypatch.setattr(agent_logs, "_detail_files", too_many)
    result = client.get("/logs/sessions", headers=AUTH).json
    assert result["status"] == "unavailable"
    assert "archive" in result["reason"]
    assert "permissions" not in result["reason"]
    assert "synthetic private" not in result["reason"]


@pytest.mark.parametrize(
    "error", [FileNotFoundError("synthetic key path"), ssl.SSLError("synthetic TLS")]
)
def test_tls_context_failure_is_a_page_unavailable_state(tmp_path, monkeypatch, error):
    _, client = admin_client(tmp_path)

    def invalid_context(self):
        raise error

    monkeypatch.setattr(AgentClient, "_tls_context", invalid_context)
    response = client.get("/logs/radius-logins")
    assert response.status_code == 200
    assert "Logs are unavailable" in response.text
    assert "synthetic" not in response.text
