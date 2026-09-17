from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from inspect import iscoroutinefunction
from typing import Any

from jsonschema import Draft202012Validator

from agentgate.core.models import ToolDefinition


@dataclass
class RegisteredTool:
    definition: ToolDefinition
    handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class Registry:
    def __init__(self):
        self.tools: dict[str, RegisteredTool] = {}

    def register(self, definition, handler):
        if not iscoroutinefunction(handler):
            raise ValueError("Tool handlers must be async and cooperate with cancellation")
        if definition.name in self.tools:
            raise ValueError("Tool already registered; create a new registry for updates")
        Draft202012Validator.check_schema(definition.input_schema)
        if definition.input_schema.get("additionalProperties") is not False:
            raise ValueError("Tool schemas must reject unknown arguments")
        if definition.output_schema:
            Draft202012Validator.check_schema(definition.output_schema)
        self.tools[definition.name] = RegisteredTool(definition, handler)

    def definitions(self):
        return [entry.definition.model_dump(mode="json") for entry in self.tools.values()]
