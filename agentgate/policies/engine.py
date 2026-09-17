"""Data-only rule matching; no executable expressions in policy files."""

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, model_validator

from agentgate.core.hashing import digest
from agentgate.core.models import Decision, StrictModel


class Match(StrictModel):
    tool: str | list[str] | None = None
    operation: str | list[str] | None = None
    risk_level: str | list[str] | None = None
    environment: str | list[str] | None = None
    actor_id: str | list[str] | None = None
    tenant_id: str | list[str] | None = None
    same_tenant: bool | None = None
    argument_equals: dict[str, Any] | None = None
    amount_gte: float | None = None
    amount_lte: float | None = None
    finding_category: str | list[str] | None = None
    finding_severity: str | list[str] | None = None
    is_write: bool | None = None
    approval_exists: bool | None = None


class Rule(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    match: Match
    decision: Decision


class Policy(StrictModel):
    version: str | int
    default_decision: Literal["DENY"] = "DENY"
    rules: list[Rule] = Field(max_length=200)

    @model_validator(mode="after")
    def unique_rules(self):
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("Duplicate rule IDs")
        return self

    @property
    def digest(self):
        return digest(self.model_dump(mode="json"))

    @classmethod
    def load(cls, path):
        content = Path(path).read_text()
        if len(content) > 131072:
            raise ValueError("Policy exceeds 128 KiB")
        return cls.model_validate(yaml.safe_load(content))

    def evaluate(self, request, tool, findings, same_tenant=True, approved=False):
        values = {
            "tool": tool.name,
            "operation": tool.operation.value,
            "risk_level": tool.risk_level.value,
            "environment": request.context.environment,
            "actor_id": request.context.actor_id,
            "tenant_id": request.context.tenant_id,
            "same_tenant": same_tenant,
            "is_write": tool.operation.value != "read",
            "approval_exists": approved,
        }

        def matches(rule):
            for key, expected in rule.match.model_dump(exclude_none=True).items():
                choices = expected if isinstance(expected, list) else [expected]
                if key == "argument_equals":
                    if any(request.arguments.get(k) != v for k, v in expected.items()):
                        return False
                elif key.startswith("amount_"):
                    amount = request.arguments.get("amount")
                    if type(amount) not in (int, float):
                        return False
                    if (
                        key == "amount_gte"
                        and amount < expected
                        or key == "amount_lte"
                        and amount > expected
                    ):
                        return False
                elif key.startswith("finding_"):
                    field = key.removeprefix("finding_")
                    if not any(f.get(field) in choices for f in findings):
                        return False
                elif values[key] not in choices:
                    return False
            return True

        matched = [r for r in self.rules if matches(r)]
        outcomes = {r.decision for r in matched}
        if Decision.DENY in outcomes:
            decision = Decision.DENY
        elif Decision.REQUIRE_HUMAN_APPROVAL in outcomes and not approved:
            decision = Decision.REQUIRE_HUMAN_APPROVAL
        elif Decision.REDACT_AND_CONTINUE in outcomes:
            decision = Decision.REDACT_AND_CONTINUE
        elif Decision.ALLOW in outcomes:
            decision = Decision.ALLOW
        else:
            decision = Decision.DENY
        if tool.requires_approval_by_default and decision == Decision.ALLOW and not approved:
            decision = Decision.REQUIRE_HUMAN_APPROVAL
        return decision, [r.id for r in matched]
