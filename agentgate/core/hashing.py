"""Canonical JSON rejects NaN and binds authority, not incidental trace identifiers."""

import hashlib
import json
from typing import Any


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def request_hash(request, policy_digest: str) -> str:
    context = request.context
    return digest(
        {
            "tool": request.tool_name,
            "arguments": request.arguments,
            "actor": context.actor_id,
            "tenant": context.tenant_id,
            "agent": context.agent_id,
            "environment": context.environment,
            "policy": policy_digest,
        }
    )
