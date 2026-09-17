"""Only the built-in FakeEnvironment is admitted; no arbitrary adapters execute."""

from typing import Protocol

from agentgate.demo import FakeEnvironment


class TaskEnvironment(Protocol):
    async def call(self, name: str, arguments: dict) -> dict: ...
    def snapshot(self) -> dict: ...


__all__ = ["FakeEnvironment", "TaskEnvironment"]
