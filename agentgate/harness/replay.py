"""Offline evidence verification; does not invoke agents, tools or the runtime."""

import argparse
import json
from pathlib import Path

from agentgate.core.hashing import digest


def verify_report(report):
    failures = []
    events = report.get("events", [])
    if not events:
        return ["Missing trajectory"]
    previous = None
    state = report.get("initial_state_hash")
    for index, event in enumerate(events):
        if event.get("sequence") != index or event.get("previous_event_hash") != previous:
            failures.append(f"Event {index}: chain continuity")
        if event.get("event_hash") != digest({k: v for k, v in event.items() if k != "event_hash"}):
            failures.append(f"Event {index}: hash mismatch")
        if (
            event.get("run_id") != report.get("run_id")
            or event.get("task_id") != report.get("task_id")
            or event.get("mode") != report.get("mode")
        ):
            failures.append(f"Event {index}: identity mismatch")
        if event.get("state_hash_before") != state:
            failures.append(f"Event {index}: state continuity")
        if "snapshot" in event and digest(event["snapshot"]) != event.get("snapshot_hash"):
            failures.append(f"Event {index}: sanitized snapshot mismatch")
        state = event.get("state_hash_after")
        previous = event.get("event_hash")
    if state != report.get("final_state_hash") or previous != report.get("trajectory_hash"):
        failures.append("Final state or trajectory mismatch")
    if (
        events[0].get("event_type") != "run_started"
        or events[-1].get("event_type") != "run_finished"
    ):
        failures.append("Incomplete run")
    summary = events[-1].get("summary", {})
    for key in (
        "metrics",
        "status",
        "seed",
        "grader_failures",
        "harness_version",
        "dataset_version",
        "policy_version",
    ):
        if key not in summary or summary[key] != report.get(key):
            failures.append("Summary mismatch: " + key)
    if events[0].get("seed") != report.get("seed"):
        failures.append("Initial seed mismatch")
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    if Path(args.run_id).name != args.run_id:
        parser.error("run-id must be an identifier")
    report = json.loads(Path("evals/reports/runs", args.run_id + ".json").read_text())
    failures = verify_report(report)
    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "failures": failures,
                "status": "failed" if failures else "passed",
            }
        )
    )
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
