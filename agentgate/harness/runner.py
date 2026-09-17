"""Same script, seed and initial state in a bounded fake-only experiment."""

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentgate.config import Settings
from agentgate.core.hashing import digest
from agentgate.core.models import RequestContext, ToolCallRequest
from agentgate.demo import FakeEnvironment, make_runtime
from agentgate.harness.adapters import FakeAgent
from agentgate.harness.faults import validate_fault
from agentgate.harness.replay import verify_report
from agentgate.harness.sandbox import check_action
from agentgate.harness.task import HarnessTask, load_task
from agentgate.harness.trajectory import Recorder
from agentgate.security.inspection import redact


async def run_task(task_id, mode="protected", seed=42, fault_profile=None, task=None):
    if mode == "compare":
        baseline = await run_task(task_id, "baseline", seed, fault_profile, task)
        protected = await run_task(task_id, "protected", seed, fault_profile, task)
        return {
            "task_id": task_id,
            "seed": seed,
            "mode": mode,
            "baseline": baseline,
            "protected": protected,
            "side_effect_delta": baseline["metrics"]["side_effects"]
            - protected["metrics"]["side_effects"],
        }
    if mode not in {"baseline", "protected", "fault-injection"}:
        raise ValueError("Unsupported run mode")
    task = HarnessTask.model_validate(task) if task is not None else load_task(task_id, seed)
    task.seed = seed
    fault = fault_profile or task.fault_profile
    validate_fault(fault)
    environment = FakeEnvironment(task.initial_state, fault)
    runtime = make_runtime(
        # BaseSettings supports _env_file; synthetic runs must ignore operator dotenv files.
        Settings(_env_file=None, database_url="sqlite:///:memory:", otel_enabled=False),  # type: ignore[call-arg]
        initialize=True,
        environment=environment,
    )
    context = RequestContext(**task.identity)
    recorder = Recorder("run-" + uuid4().hex, task, mode)
    state = initial = digest(environment.snapshot())
    recorder.append(
        "run_started",
        state,
        state,
        fault_profile=fault,
        seed=seed,
        policy_version=runtime.policy.version,
        policy_hash=runtime.policy.digest,
        plan_hash=digest(task.agent_actions),
    )
    safe_snapshot = redact(environment.snapshot())
    recorder.append(
        "state_snapshot", state, state, snapshot=safe_snapshot, snapshot_hash=digest(safe_snapshot)
    )
    agent = FakeAgent()
    agent.start(task, task.available_tools)
    recorder.append("agent_message", state, state, redacted_input=task.user_prompt)
    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    failures: list[str] = []
    approvals, blocked, findings, replays, replay_successes = 0, 0, [], 0, 0
    approval_id = None
    steps = 0
    limit_breaches = 0

    async def perform(proposed):
        nonlocal approval_id, replays, replay_successes
        if proposed.get("approval"):
            replays += 1
            if mode == "baseline":
                original = next(a for a in task.agent_actions if "tool_name" in a)
                data = await environment.call(original["tool_name"], original["arguments"])
                replay_successes += int(replays > 1)
                return {
                    "decision": "ALLOW",
                    "executed": True,
                    "result": {"success": True, "data": data},
                    "findings": [],
                }
            response = await runtime.resolve_approval(approval_id or "missing", context, True)
            if replays > 1 and response.get("executed"):
                replay_successes += 1
            return response
        if mode == "baseline":
            try:
                data = await environment.call(proposed["tool_name"], proposed["arguments"])
                return {
                    "decision": "ALLOW",
                    "executed": True,
                    "result": {"success": True, "data": data},
                    "findings": [],
                }
            except Exception:
                return {
                    "decision": "ALLOW",
                    "executed": True,
                    "result": {"success": False, "error_code": "TOOL_FAILED"},
                    "findings": [],
                }
        response = await runtime.call(ToolCallRequest(**proposed, context=context))
        approval_id = response.get("approval_id") or approval_id
        return response

    try:
        for index, _ in enumerate(task.agent_actions):
            proposed = agent.next_action(results[-1] if results else {})
            error = check_action(proposed, task, index)
            remaining = task.timeout_seconds - (time.perf_counter() - started)
            if error or remaining <= 0:
                limit_breaches += 1
                failures.append(error or "DURATION_LIMIT")
                recorder.append("run_failed", state, state, error_code=failures[-1])
                break
            steps += 1
            recorder.append(
                "tool_proposed",
                state,
                state,
                tool_name=proposed.get("tool_name"),
                redacted_input=proposed,
            )
            call_started = time.perf_counter()
            try:
                response = await asyncio.wait_for(perform(proposed), remaining)
            except TimeoutError:
                limit_breaches += 1
                failures.append("DURATION_LIMIT")
                recorder.append("run_failed", state, state, error_code="DURATION_LIMIT")
                break
            except (ValueError, TypeError):
                response = {
                    "decision": "DENY",
                    "executed": False,
                    "findings": [],
                    "result": {"success": False, "error_code": "INVALID_REQUEST"},
                }
            after = digest(environment.snapshot())
            event_type = "approval_resolved" if proposed.get("approval") else "policy_decision"
            recorder.append(
                event_type,
                state,
                state,
                decision=response["decision"],
                rule_ids=response.get("matched_rule_ids", []),
                approval_id=response.get("approval_id"),
            )
            if response.get("approval_id"):
                approvals += 1
                recorder.append(
                    "approval_requested", state, state, approval_id=response["approval_id"]
                )
            if response.get("executed"):
                recorder.append("tool_started", state, state, tool_name=proposed.get("tool_name"))
            recorder.append(
                "tool_result",
                state,
                after,
                redacted_output=response,
                latency_ms=(time.perf_counter() - call_started) * 1000,
                error_code=response["result"].get("error_code"),
                tool_name=proposed.get("tool_name"),
            )
            state = after
            results.append(response)
            blocked += int(response["decision"] == "DENY")
            for finding in response.get("findings", []):
                findings.append(finding)
                recorder.append("finding", state, state, redacted_output=finding)
        final = results[-1] if results else {}
        if mode != "baseline":
            expected = task.expected_outcome
            for key, actual in [
                ("decision", final.get("decision")),
                ("tool_must_execute", final.get("executed")),
                ("error_code", final.get("result", {}).get("error_code")),
                ("side_effects", len(environment.effects)),
                ("attempts", environment.calls),
            ]:
                if key in expected and expected[key] != actual:
                    failures.append(f"{key}: expected {expected[key]!r}, got {actual!r}")
            categories = {finding["category"] for finding in findings}
            for category in expected.get("required_findings", []):
                if category not in categories:
                    failures.append("Missing finding: " + category)
            if replay_successes:
                failures.append("Approval replay executed")
        snapshot = redact(environment.snapshot())
        recorder.append(
            "state_snapshot", state, state, snapshot=snapshot, snapshot_hash=digest(snapshot)
        )
        recorder.append("agent_message", state, state, redacted_output=agent.finish(final))
        attempts = environment.calls
        executed = sum(bool(response.get("executed")) for response in results)
        report = {
            "run_id": recorder.run_id,
            "harness_run_id": recorder.run_id,
            "task_id": task.task_id,
            "mode": mode,
            "seed": seed,
            "harness_version": "1",
            "dataset_version": "1",
            "policy_version": runtime.policy.version,
            "initial_state_hash": initial,
            "final_state_hash": state,
            "events": recorder.events,
            "status": "failed" if failures else "completed",
            "grader_failures": failures,
            "metrics": {
                "steps": steps,
                "tool_calls": executed,
                "blocked_calls": blocked,
                "approvals": approvals,
                "findings": len(findings),
                "side_effects": len(environment.effects),
                "attempts": attempts,
                "retries": max(0, attempts - executed),
                "approval_replay_attempts": max(0, replays - 1),
                "approval_replay_successes": replay_successes,
                "limit_breaches": limit_breaches,
                "duration_ms": (time.perf_counter() - started) * 1000,
            },
            "limitations": [
                "Trusted in-process fake simulation, not an OS sandbox.",
                "Replay verifies chained evidence; raw-state hashes cannot be reconstructed from redacted snapshots.",
                "Hash chains detect mutation, not a fully rewritten unsigned report.",
            ],
        }
        recorder.append(
            "run_finished",
            state,
            state,
            summary={
                key: report[key]
                for key in (
                    "metrics",
                    "status",
                    "seed",
                    "grader_failures",
                    "harness_version",
                    "dataset_version",
                    "policy_version",
                )
            },
        )
        report["trajectory_hash"] = recorder.events[-1]["event_hash"]
        report["replay_failures"] = verify_report(report)
        return report
    finally:
        runtime.store.engine.dispose()


def persist_report(report, path=None):
    if report.get("mode") == "compare":
        for mode in ("baseline", "protected"):
            persist_report(report[mode])
    else:
        directory = Path("evals/reports/runs")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (report["run_id"] + ".json")).write_text(json.dumps(report, indent=2) + "\n")
    if path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", default="refund-approval")
    parser.add_argument(
        "--mode", default="compare", choices=["baseline", "protected", "compare", "fault-injection"]
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fault-profile")
    parser.add_argument("--report")
    args = parser.parse_args()
    report = asyncio.run(run_task(args.task, args.mode, args.seed, args.fault_profile))
    persist_report(report, args.report)
    reports = [report["baseline"], report["protected"]] if args.mode == "compare" else [report]
    print(
        json.dumps([{k: v for k, v in item.items() if k != "events"} for item in reports], indent=2)
    )
    raise SystemExit(any(item["grader_failures"] or item["replay_failures"] for item in reports))


if __name__ == "__main__":
    main()
