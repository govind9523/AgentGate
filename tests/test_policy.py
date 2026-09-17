import itertools

import pytest
from pydantic import ValidationError

from agentgate.core.hashing import request_hash
from agentgate.core.models import Decision, RequestContext, ToolCallRequest, ToolDefinition
from agentgate.policies.engine import Policy


def tool():
    return ToolDefinition(
        name="read_orders",
        description="Read synthetic order",
        operation="read",
        risk_level="low",
        input_schema={"type": "object", "additionalProperties": False},
    )


@pytest.mark.parametrize(
    "outcomes", [list(c) for n in range(5) for c in itertools.combinations(list(Decision), n)]
)
def test_decision_precedence_is_independent_of_rule_order(outcomes):
    request = ToolCallRequest(tool_name="read_orders", arguments={}, context=RequestContext())
    expected = next(
        (
            d
            for d in (
                Decision.DENY,
                Decision.REQUIRE_HUMAN_APPROVAL,
                Decision.REDACT_AND_CONTINUE,
                Decision.ALLOW,
            )
            if d in outcomes
        ),
        Decision.DENY,
    )
    for order in (outcomes, outcomes[::-1]):
        policy = Policy.model_validate(
            {
                "version": 1,
                "rules": [
                    {"id": str(i), "description": "Matrix rule", "match": {}, "decision": d}
                    for i, d in enumerate(order)
                ],
            }
        )
        actual, _ = policy.evaluate(request, tool(), [])
        assert actual == expected


@pytest.mark.parametrize(
    "match,arguments,matches",
    [
        ({"tool": ["read_orders", "other"]}, {}, True),
        ({"tool": "other"}, {}, False),
        ({"environment": ["staging", "development"]}, {}, True),
        ({"actor_id": "someone-else"}, {}, False),
        ({"tenant_id": "tenant-other"}, {}, False),
        ({"same_tenant": True}, {}, True),
        ({"argument_equals": {"currency": "USD"}}, {"currency": "USD"}, True),
        ({"argument_equals": {"currency": "USD"}}, {"currency": "EUR"}, False),
        ({"amount_gte": 1000}, {"amount": 1000}, True),
        ({"amount_gte": 1000}, {"amount": 999.99}, False),
        ({"amount_lte": 1000}, {"amount": 1000}, True),
        ({"amount_lte": 1000}, {"amount": 1000.01}, False),
        ({"amount_gte": 1000}, {"amount": "9999"}, False),
        ({"amount_gte": 0}, {"amount": True}, False),
        ({"is_write": False}, {}, True),
        ({"approval_exists": True}, {}, False),
    ],
)
def test_policy_match_conditions(match, arguments, matches):
    policy = Policy.model_validate(
        {
            "version": 1,
            "rules": [
                {"id": "rule", "description": "Match rule", "match": match, "decision": "ALLOW"}
            ],
        }
    )
    request = ToolCallRequest(
        tool_name="read_orders", arguments=arguments, context=RequestContext()
    )
    decision, _ = policy.evaluate(request, tool(), [])
    assert decision == (Decision.ALLOW if matches else Decision.DENY)


def test_unknown_policy_field_and_duplicate_rules_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "rule",
                        "description": "Invalid",
                        "match": {"python": "True"},
                        "decision": "ALLOW",
                    }
                ],
            }
        )
    rule = {"id": "same", "description": "Duplicate", "match": {}, "decision": "ALLOW"}
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "rules": [rule, rule]})


def test_hash_binds_authority_and_arguments_but_not_trace_ids():
    request = ToolCallRequest(
        tool_name="read_orders", arguments={"a": 1, "b": 2}, context=RequestContext()
    )
    hashed = request_hash(request, "v1")
    assert request_hash(request.model_copy(update={"arguments": {"b": 2, "a": 1}}), "v1") == hashed
    for change in (
        {"actor_id": "different"},
        {"tenant_id": "different"},
        {"environment": "production"},
        {"agent_id": "different"},
    ):
        assert (
            request_hash(
                request.model_copy(update={"context": request.context.model_copy(update=change)}),
                "v1",
            )
            != hashed
        )
    assert request_hash(request.model_copy(update={"arguments": {"a": 2, "b": 2}}), "v1") != hashed
    assert request_hash(request, "v2") != hashed
