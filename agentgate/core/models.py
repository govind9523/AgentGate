"""Validated contracts. RequestContext is constructed by a trusted caller."""

from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    REDACT_AND_CONTINUE = "REDACT_AND_CONTINUE"


class Operation(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RequestContext(StrictModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()), max_length=100)
    trace_id: str = Field(default_factory=lambda: uuid4().hex, max_length=100)
    actor_id: str = Field(default="support-agent", min_length=1, max_length=100)
    tenant_id: str = Field(default="tenant-demo", min_length=1, max_length=100)
    agent_id: str = Field(default="support-agent-v1", min_length=1, max_length=100)
    environment: str = Field(default="development", pattern="^(development|staging|production)$")
    purpose: str = Field(default="Support request", max_length=500)
    source: str = Field(default="sdk", max_length=50)
    metadata: dict[str, str] = Field(default_factory=dict)


class ToolCallRequest(StrictModel):
    tool_name: str = Field(min_length=2, max_length=64)
    arguments: dict[str, Any]
    context: RequestContext
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128)
    requested_by_model: bool = True


class ToolDefinition(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    description: str = Field(max_length=2000)
    operation: Operation
    risk_level: RiskLevel
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    allowed_environments: list[str] = Field(default_factory=lambda: ["development"])
    allowed_tenants: list[str] | None = None
    requires_approval_by_default: bool = False
    timeout_seconds: float = Field(default=10, ge=0.1, le=120)
    max_retries: int = Field(default=0, ge=0, le=3)
    owner: str = "support-platform"
    version: str = "1.0.0"
    enabled: bool = True

    @model_validator(mode="after")
    def safe_registration(self):
        if self.operation != Operation.READ and "production" in self.allowed_environments:
            raise ValueError("Write, delete and execute tools cannot register production access")
        if self.operation != Operation.READ and self.max_retries:
            raise ValueError("Only reads may retry automatically")
        return self


class SecurityFinding(StrictModel):
    code: str
    category: str
    severity: RiskLevel
    message: str
    location: str
    evidence_hash: str | None = None
    remediation: str = "Review the request and policy before retrying."


class ToolResult(StrictModel):
    success: bool
    data: Any = None
    error_code: str | None = None
    safe_message: str | None = None
    findings: list[SecurityFinding] = Field(default_factory=list)
    tool_execution_ms: float | None = None
