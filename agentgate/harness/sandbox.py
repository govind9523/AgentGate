"""Bounds for trusted fake code, NOT an OS security boundary.

No network/subprocess/filesystem adapters are admitted. Arbitrary untrusted code
requires separate-process/container resource and OS isolation.
"""

from agentgate.core.hashing import canonical


def check_action(action, task, step):
    if step >= task.max_steps:
        return "MAX_STEPS"
    if len(canonical(action).encode()) > 65536:
        return "PAYLOAD_LIMIT"
    if "approval" not in action and action.get("tool_name") not in task.available_tools:
        return "TOOL_NOT_ALLOWED"
    return None
