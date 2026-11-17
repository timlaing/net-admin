"""Evaluate the actual status expression without executing a workflow or native code."""

import ast
import re
from pathlib import Path

import pytest
import yaml

REQUIRED = (
    "prepare",
    "verify",
    "lint",
    "publish",
    "publish-addon",
    "manifests",
    "verify-public-images",
    "publish-installer",
)


def status_job():
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml"
    return yaml.safe_load(workflow.read_text())["jobs"]["publication-status"]


def evaluate_status(results, version):
    expression = status_job()["steps"][-1]["env"]["PUBLICATION_STATE"]
    expression = expression.strip().removeprefix("${{").removesuffix("}}").strip()
    expression = expression.replace(
        "contains(needs.prepare.outputs.version, '-')", repr("-" in version)
    )
    expression = re.sub(
        r"needs\.([A-Za-z0-9_-]+)\.result",
        lambda match: repr(results.get(match[1], "")),
        expression,
    )
    python = expression.replace("&&", "and").replace("||", "or")
    tree = ast.parse(f"({python})", mode="eval")

    def boolean(node):
        value = visit(node.values[0])
        for child in node.values[1:]:
            if isinstance(node.op, ast.And) and not value:
                return value
            if isinstance(node.op, ast.Or) and value:
                return value
            value = visit(child)
        return value

    def visit(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Compare):
            assert len(node.ops) == 1
            assert isinstance(node.ops[0], ast.Eq)
            return visit(node.left) == visit(node.comparators[0])
        if isinstance(node, ast.BoolOp):
            return boolean(node)
        raise AssertionError("Unsupported workflow expression syntax")

    return visit(tree.body)


def successful_results():
    return dict.fromkeys((*REQUIRED, "promote-latest"), "success")


def test_status_has_every_required_job_as_a_direct_dependency():
    job = status_job()
    assert set(job["needs"]) == set(REQUIRED) | {"promote-latest"}
    assert job["if"] == "always()"


def test_successful_stable_publication_is_ready():
    assert evaluate_status(successful_results(), "2026.11.3") == "ready"


@pytest.mark.parametrize("job", REQUIRED)
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", ""])
def test_any_unsuccessful_or_missing_required_job_prevents_ready(job, result):
    results = successful_results()
    results[job] = result
    assert evaluate_status(results, "2026.11.3") == "failed"


def test_failed_verification_and_skipped_downstream_jobs_cannot_report_ready():
    results = dict.fromkeys((*REQUIRED, "promote-latest"), "skipped")
    results.update(prepare="success", verify="failure", lint="success")
    assert evaluate_status(results, "2026.11.3") == "failed"


@pytest.mark.parametrize("version", ["2026.11.3", "2026.11.3-rc.1"])
@pytest.mark.parametrize("result", ["failure", "cancelled", "", "skipped"])
def test_only_prereleases_may_skip_latest_promotion(version, result):
    results = successful_results() | {"promote-latest": result}
    expected = "ready" if result == "skipped" and "-" in version else "failed"
    assert evaluate_status(results, version) == expected


def test_skipped_prerelease_promotion_does_not_exempt_other_gates():
    results = successful_results() | {"promote-latest": "skipped", "lint": "failure"}
    assert evaluate_status(results, "2026.11.3-rc.1") == "failed"
