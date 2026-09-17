"""Explicit administrator-configured HTTP tools; URLs never come from agent arguments."""

import re
from urllib.parse import urlparse

import httpx


class HTTPToolAdapter:
    def __init__(self, base_url: str, allowed_hosts: set[str], client: httpx.AsyncClient):
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in allowed_hosts
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Tool origin must be an explicitly allowed HTTPS host")
        self.base_url, self.client = base_url.rstrip("/"), client

    async def call(self, tool_name: str, arguments: dict) -> dict:
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", tool_name):
            raise ValueError("Invalid registered tool name")
        # Never follow redirects into an origin that was not approved.
        async with self.client.stream(
            "POST",
            f"{self.base_url}/tools/{tool_name}",
            json=arguments,
            follow_redirects=False,
            timeout=10,
        ) as response:
            response.raise_for_status()
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 262144:
                    raise ValueError("Tool response exceeds limit")
                chunks.append(chunk)
            import json

            result = json.loads(b"".join(chunks))
            if not isinstance(result, dict):
                raise ValueError("Tool response must be an object")
            return result
