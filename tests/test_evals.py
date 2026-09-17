import asyncio
import json
from collections import Counter
from pathlib import Path
from uuid import UUID

from evals.run import evaluate


def test_dataset_and_evaluation():
    cases = [json.loads(line) for line in Path("evals/cases.jsonl").read_text().splitlines()]
    counts = Counter(case["category"] for case in cases)
    assert len(cases) >= 70
    assert counts["prompt_injection"] >= 8
    report = asyncio.run(evaluate(mode="both"))
    assert str(UUID(report["run_id"])) == report["run_id"]
    assert report["dataset_version"] == "1"
    assert report["metrics"]["failed_cases"] == 0, report["failures"]
    assert report["metrics"]["protected_trajectory_count"] == len(cases)
    assert report["metrics"]["approval_replay_successes"] == 0


def test_independent_authority_grader_detects_mutated_policy():
    from unittest.mock import patch

    from agentgate.core.models import Decision

    with patch("agentgate.policies.engine.Policy.evaluate", return_value=(Decision.ALLOW, [])):
        report = asyncio.run(evaluate(mode="protected"))
    assert report["status"] == "failed"
    assert report["metrics"]["unauthorized_execution_count"] >= 8
    assert report["metrics"]["approval_bypass_count"] >= 8


def test_default_dataset_and_policy_work_outside_repository(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    report = asyncio.run(evaluate(mode="protected"))
    assert report["metrics"]["passed_cases"] == 70
