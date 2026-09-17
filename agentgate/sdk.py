"""Small HTTP SDK. Identity is supplied by the service-side credential mapping."""

import httpx


class AgentGateClient:
    def __init__(self, base_url: str, token: str):
        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": "Bearer " + token},
            timeout=130,
            follow_redirects=False,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.client.aclose()

    async def call(
        self, tool_name: str, arguments: dict, *, purpose="Support request", idempotency_key=None
    ):
        response = await self.client.post(
            "/api/v1/tool-calls",
            json={
                "tool_name": tool_name,
                "arguments": arguments,
                "purpose": purpose,
                "idempotency_key": idempotency_key,
            },
        )
        if response.status_code not in (200, 202, 403, 409, 422, 502, 504):
            response.raise_for_status()
        return response.json()
