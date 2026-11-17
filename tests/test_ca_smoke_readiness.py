"""Exercise only the bounded readiness helper from the real CA image smoke script."""

import ast
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest


def smoke_helper(responses):
    script = Path(__file__).resolve().parents[1] / "Tools/smoke_ca_runtime.sh"
    python = script.read_text().split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    tree = ast.parse(python)
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "wait_for_issuers"
    )
    calls, waits = [], []
    sequence = iter(responses)

    def get(path, **kwargs):
        calls.append((path, kwargs))
        response = next(sequence)
        if isinstance(response, Exception):
            raise response
        return response

    namespace = {
        "client": SimpleNamespace(get=get),
        "httpx": httpx,
        "time": SimpleNamespace(sleep=waits.append),
    }
    module = ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[]))
    exec(compile(module, str(script), "exec"), namespace)  # noqa: S102 - our tracked helper, mocked I/O only
    return namespace["wait_for_issuers"], calls, waits


def response(status, ready):
    return SimpleNamespace(status_code=status, json=lambda: {"ready": ready})


def test_smoke_waits_for_supervisor_reconciliation():
    ready = response(200, True)
    check, calls, waits = smoke_helper([response(503, False), response(200, False), ready])
    assert check() is ready
    assert waits == [1, 1]
    assert calls == [("/ready", {"timeout": 3})] * 3


def test_smoke_can_recover_from_transient_readiness_errors():
    ready = response(200, True)
    check, calls, waits = smoke_helper([httpx.ReadTimeout("synthetic timeout"), ready])
    assert check() is ready
    assert len(calls) == 2
    assert waits == [1]


@pytest.mark.parametrize(
    "result",
    [response(503, False), response(200, False), httpx.ReadTimeout("synthetic-private-diagnostic")],
)
def test_smoke_failure_is_bounded_and_does_not_expose_diagnostics(result):
    check, calls, waits = smoke_helper([result] * 30)
    with pytest.raises(RuntimeError, match="startup budget") as caught:
        check()
    assert len(calls) == 30
    assert waits == [1] * 29
    assert "synthetic-private-diagnostic" not in str(caught.value)
