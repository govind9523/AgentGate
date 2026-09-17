"""Explainable heuristics, not a complete prompt-injection or DLP detector."""

import re
from typing import Any

from agentgate.core.hashing import digest
from agentgate.core.models import RiskLevel, SecurityFinding

SECRET_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|secrets?|token|api_key|authorization|private_key|secret_access_key|credentials)$",
    re.I,
)
PATTERNS = {
    "secret": re.compile(
        r"AKIA[0-9A-Z]{16}|(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})|Bearer\s+[A-Za-z0-9._~+/-]+=*|-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----|(?:postgres(?:ql)?|mysql|mongodb)://[^\s]+:[^\s]+@[^\s]+|(?:api[_-]?key|password|secret|token)\s*[:=]\s*[\"']?[^\s\"',;}]+",
        re.I,
    ),
    "pii": re.compile(
        r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|(?<!\w)(?:\+\d[\d ()-]{8,}\d|\d{3}-\d{2}-\d{4}|(?:\d[ -]?){13,19})(?!\w)",
        re.I,
    ),
    "prompt_injection": re.compile(
        r"ignore\s+(?:all\s+)?(?:previous\s+instructions|policy|instructions)|reveal\s+(?:the\s+)?(?:system\s+prompt|customer\s+record)|call\s+this\s+tool\s+immediately|send\s+all\s+records|disable\s+safety\s+rules",
        re.I,
    ),
    "argument_safety": re.compile(
        r"(?:\.\.[/\\]|%2e%2e|\$\(|`|;\s*(?:rm|curl|wget|sh)\b|https?://)", re.I
    ),
}


def secret_key(key: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower().replace("-", "_")
    return SECRET_KEY.search(normalized) is not None


def inspect(payload: Any, location: str = "arguments") -> list[dict]:
    findings = []

    def walk(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                if secret_key(key) and item != "[REDACTED]":
                    add("secret", item, path)
                walk(item, path)
        elif isinstance(value, list):
            for item in value:
                walk(item, path)
        elif type(value) is int and 10**12 <= abs(value) < 10**19:
            add("pii", value, path)
        elif isinstance(value, str):
            for category, pattern in PATTERNS.items():
                if category == "argument_safety" and location != "arguments":
                    continue
                if pattern.search(value):
                    add(category, value, path)

    def add(category, evidence, path):
        findings.append(
            SecurityFinding(
                code=category.upper(),
                category=category,
                severity=RiskLevel.HIGH
                if category in {"prompt_injection", "argument_safety"}
                else RiskLevel.MEDIUM,
                message=f"{category.replace('_', ' ').capitalize()} pattern detected.",
                location=path,
                evidence_hash=digest(evidence),
            ).model_dump(mode="json")
        )

    walk(payload, location)
    return findings


def redact(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {
            redact(str(key)): "[REDACTED]" if secret_key(str(key)) else redact(value)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    if type(payload) is int and 10**12 <= abs(payload) < 10**19:
        return "[REDACTED]"
    if isinstance(payload, str):
        for category in ("secret", "pii"):
            payload = PATTERNS[category].sub("[REDACTED]", payload)
    return payload
