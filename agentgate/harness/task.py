"""Declarative, synthetic tasks; identity comes from the manifest, never the agent."""

from copy import deepcopy
from typing import Any

from pydantic import BaseModel, Field

from agentgate.demo import INITIAL_STATE


class HarnessTask(BaseModel):
    task_id: str
    description: str = "Synthetic deterministic support task"
    initial_state: dict[str, Any] = Field(default_factory=lambda: deepcopy(INITIAL_STATE))
    available_tools: list[str] = Field(
        default_factory=lambda: [
            "read_orders",
            "read_customer",
            "search_kb",
            "refund_payment",
            "update_customer_email",
            "send_email",
        ]
    )
    user_prompt: str = "Complete the scripted support request."
    expected_outcome: dict[str, Any] = Field(default_factory=dict)
    agent_actions: list[dict[str, Any]]
    identity: dict[str, str] = Field(default_factory=dict)
    seed: int = 0
    max_steps: int = Field(default=12, ge=1, le=20)
    timeout_seconds: float = Field(default=5, gt=0, le=120)
    fault_profile: str | None = None


def action(tool, **arguments):
    return {"tool_name": tool, "arguments": arguments}


def load_task(task_id, seed=0):
    read = action("read_customer", user_id="u-100")
    refund = action("refund_payment", user_id="u-100", amount=5000, currency="USD")
    tasks: dict[str, tuple[list[dict[str, Any]], dict[str, Any], str | None]] = {
        "allowed-read": ([read], {"decision": "ALLOW", "tool_must_execute": True}, None),
        "refund-approval": (
            [refund],
            {"decision": "REQUIRE_HUMAN_APPROVAL", "tool_must_execute": False, "side_effects": 0},
            None,
        ),
        "cross-tenant": (
            [action("read_orders", user_id="u-200")],
            {"decision": "DENY", "tool_must_execute": False},
            None,
        ),
        "prompt-injection": (
            [action("search_kb", query="injection")],
            {"error_code": "TOOL_RESPONSE_BLOCKED", "required_findings": ["prompt_injection"]},
            "prompt_injection",
        ),
        "secret-leakage": (
            [action("search_kb", query="credentials")],
            {"decision": "ALLOW", "required_findings": ["secret", "pii"]},
            None,
        ),
        "slow-tool": ([read], {"error_code": "TOOL_TIMEOUT", "attempts": 2}, "slow_tool"),
        "poisoned-description": (
            [read],
            {
                "decision": "DENY",
                "tool_must_execute": False,
                "required_findings": ["prompt_injection"],
            },
            "poisoned_tool_description",
        ),
        "malformed-output": (
            [read],
            {"error_code": "TOOL_RESPONSE_BLOCKED"},
            "malformed_tool_output",
        ),
        "tool-failure": ([read], {"error_code": "TOOL_FAILED", "attempts": 2}, "tool_failure"),
        "approval-replay": (
            [refund, {"approval": True}, {"approval": True}],
            {
                "error_code": "APPROVAL_MISMATCH",
                "side_effects": 1,
                "action_authority": ["REQUIRE_HUMAN_APPROVAL", "ALLOW", "DENY"],
            },
            None,
        ),
        "idempotency": (
            [
                {
                    **action("refund_payment", user_id="u-100", amount=50, currency="USD"),
                    "idempotency_key": "same",
                }
            ]
            * 2,
            {"decision": "ALLOW", "side_effects": 1},
            None,
        ),
    }
    if task_id not in tasks:
        raise ValueError("Unknown harness task")
    actions, expected, fault = tasks[task_id]
    return HarnessTask(
        task_id=task_id,
        seed=seed,
        agent_actions=actions,
        expected_outcome=expected,
        fault_profile=fault,
    )
