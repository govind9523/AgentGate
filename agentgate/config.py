from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTGATE_", env_file=".env", extra="forbid")
    env: str = Field(default="development", pattern="^(development|staging|production)$")
    dev_mode: bool = False
    public_demo: bool = False
    research_enabled: bool = False
    research_api_key: SecretStr | None = None
    research_model: str = Field(default="gemini-2.5-flash", pattern=r"^gemini-[a-zA-Z0-9.-]{1,80}$")
    database_url: str = "sqlite:///./data/agentgate.db"
    policy_path: str = str(
        Path(__file__).parent / "policies/demo.yml"
        if (Path(__file__).parent / "policies/demo.yml").is_file()
        else Path(__file__).parent.parent / "policies/demo.yml"
    )
    api_token: SecretStr | None = None
    admin_token: SecretStr | None = None
    actor_id: str = "support-agent"
    tenant_id: str = "tenant-demo"
    approval_ttl_seconds: int = Field(default=600, ge=1, le=3600)
    default_timeout_seconds: float = Field(default=10, ge=0.1, le=120)
    max_request_bytes: int = Field(default=65536, ge=1024, le=65536)
    max_response_bytes: int = Field(default=262144, ge=1024, le=262144)
    max_trace_events: int = Field(default=200, ge=20, le=200)
    max_agent_steps: int = Field(default=20, ge=1, le=20)
    max_total_runtime_seconds: float = Field(default=120, ge=0.1, le=120)
    allow_raw_local_debug: bool = False
    otel_enabled: bool = False
    otel_exporter: str = Field(default="console", pattern="^console$")
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    retention_days: int = Field(default=30, ge=1, le=365)

    @model_validator(mode="after")
    def safe_settings(self):
        if self.env == "production" and self.dev_mode:
            raise ValueError("Development identity is forbidden in production")
        if self.allow_raw_local_debug:
            raise ValueError("Raw sensitive logging is not supported")
        if not self.database_url.startswith("sqlite:"):
            raise ValueError("This release supports SQLite only")
        for token in (self.api_token, self.admin_token):
            if token and len(token.get_secret_value()) < 32:
                raise ValueError("Operator tokens require at least 32 characters")
        if self.api_token and self.admin_token and self.api_token == self.admin_token:
            raise ValueError("Agent and administrator tokens must differ")
        return self
