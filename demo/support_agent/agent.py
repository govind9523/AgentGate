"""Reproducible support story without a model key or remote side effects."""

import argparse
import asyncio
import json

from agentgate.config import Settings
from agentgate.core.models import RequestContext, ToolCallRequest
from agentgate.demo import make_runtime


async def run(scenario):
    runtime = make_runtime(
        Settings(database_url="sqlite:///:memory:", otel_enabled=False), initialize=True
    )
    actions = {
        "normal-read": ("read_orders", {"user_id": "u-100"}),
        "high-value-refund": (
            "refund_payment",
            {"user_id": "u-100", "amount": 5000, "currency": "USD"},
        ),
        "prompt-injection": ("search_kb", {"query": "injection"}),
    }
    name, arguments = actions[scenario]
    try:
        result = await runtime.call(
            ToolCallRequest(tool_name=name, arguments=arguments, context=RequestContext())
        )
        print(json.dumps(result, indent=2))
    finally:
        runtime.store.engine.dispose()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenario",
        choices=["normal-read", "high-value-refund", "prompt-injection"],
        default="normal-read",
    )
    asyncio.run(run(parser.parse_args().scenario))


if __name__ == "__main__":
    main()
