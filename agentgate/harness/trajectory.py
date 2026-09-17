"""Redact first, then hash public evidence; raw state is represented by hashes only."""

from datetime import UTC, datetime

from agentgate.core.hashing import digest
from agentgate.security.inspection import redact


class Recorder:
    def __init__(self, run_id, task, mode):
        self.run_id, self.task, self.mode = run_id, task, mode
        self.events = []

    def append(self, event_type, before, after, **payload):
        event = redact(
            dict(
                run_id=self.run_id,
                task_id=self.task.task_id,
                mode=self.mode,
                sequence=len(self.events),
                timestamp=datetime.now(UTC).isoformat(),
                event_type=event_type,
                actor_id=self.task.identity.get("actor_id", "support-agent"),
                tenant_id=self.task.identity.get("tenant_id", "tenant-demo"),
                state_hash_before=before,
                state_hash_after=after,
                previous_event_hash=self.events[-1]["event_hash"] if self.events else None,
                **payload,
            )
        )
        event["event_hash"] = digest(event)
        self.events.append(event)
