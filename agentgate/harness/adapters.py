"""Provider-neutral boundary; this release admits only the scripted fake adapter."""

from typing import Protocol


class AgentAdapter(Protocol):
    def start(self, task, tools): ...
    def next_action(self, observation): ...
    def finish(self, observation): ...


class FakeAgent:
    def start(self, task, tools):
        self.actions = iter(task.agent_actions)

    def next_action(self, observation):
        return next(self.actions, None)

    def finish(self, observation):
        return {"message": "Script finished.", "last_observation": observation}
