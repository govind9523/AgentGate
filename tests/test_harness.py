import asyncio
from copy import deepcopy

from agentgate.harness.replay import verify_report
from agentgate.harness.runner import run_task


def test_compare_and_replay():
    baseline = asyncio.run(run_task("refund-approval", "baseline", 42))
    protected = asyncio.run(run_task("refund-approval", "protected", 42))
    assert baseline["initial_state_hash"] == protected["initial_state_hash"]
    assert baseline["metrics"]["side_effects"] == 1
    assert protected["metrics"]["side_effects"] == 0
    assert protected["metrics"]["approvals"] == 1
    assert verify_report(protected) == []
    changed = deepcopy(protected)
    changed["events"][1]["redacted_output"] = {"tampered": True}
    assert verify_report(changed)


def test_fault_and_approval_replay():
    report = asyncio.run(run_task("slow-tool", "protected", 1))
    assert report["metrics"]["attempts"] == 2
    assert report["metrics"]["retries"] == 1
    replay = asyncio.run(run_task("approval-replay", "protected", 1))
    assert replay["metrics"]["side_effects"] == 1
    assert replay["metrics"]["approval_replay_successes"] == 0
    assert replay["grader_failures"] == []


def test_redacted_state_and_limits():
    report = asyncio.run(run_task("secret-leakage", "baseline", 42))
    import json

    assert "customer@example.com" not in json.dumps(report)
    assert "test-secret-value-123" not in json.dumps(report)
    assert verify_report(report) == []
    from agentgate.harness.task import load_task

    task = load_task("allowed-read")
    task.agent_actions *= 3
    task.max_steps = 1
    limited = asyncio.run(run_task(task.task_id, task=task))
    assert limited["metrics"]["steps"] == 1
    assert limited["grader_failures"] == ["MAX_STEPS"]
    task.available_tools = []
    denied = asyncio.run(run_task(task.task_id, task=task))
    assert denied["metrics"]["attempts"] == 0
    assert "TOOL_NOT_ALLOWED" in denied["grader_failures"]


def test_replay_checks_sanitized_snapshot_and_raw_hash_continuity():
    from agentgate.core.hashing import digest

    report = asyncio.run(run_task("allowed-read"))
    event = report["events"][1]
    event["snapshot"]["customers"] = {}
    event["event_hash"] = digest({k: v for k, v in event.items() if k != "event_hash"})
    failures = verify_report(report)
    assert any("snapshot" in failure for failure in failures)
    assert any("continuity" in failure for failure in failures)


def test_persisted_trajectory_replays_after_redaction():
    from agentgate.security.inspection import redact
    from agentgate.storage.database import Store

    report = asyncio.run(run_task("secret-leakage", "baseline", 42))
    assert verify_report(redact(report)) == []
    store = Store("sqlite:///:memory:")
    store.initialize()
    try:
        store.persist_trajectory(report, "tenant-demo")
        stored = store.get("harness_runs", report["run_id"], "tenant-demo")
        assert verify_report(stored) == []
        assert stored == report
    finally:
        store.engine.dispose()


def test_replay_rejects_summary_tampering_and_counts_baseline_replay():
    report = asyncio.run(run_task("approval-replay", "baseline"))
    assert report["metrics"]["approval_replay_successes"] == 1
    for key, value in [("seed", 777), ("status", "invented"), ("metrics", {"side_effects": 999})]:
        changed = deepcopy(report)
        changed[key] = value
        assert verify_report(changed), key
