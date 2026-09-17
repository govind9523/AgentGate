PROFILES = {
    "prompt_injection",
    "poisoned_tool_description",
    "slow_tool",
    "malformed_tool_output",
    "tool_failure",
}


def validate_fault(profile):
    if profile is not None and profile not in PROFILES:
        raise ValueError("Unknown deterministic fault profile")
