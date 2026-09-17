"""One authorization path for SDK, HTTP, demos and protected harness calls."""

import asyncio
import time
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator
from opentelemetry import trace

from agentgate.core.hashing import canonical, digest, request_hash
from agentgate.core.models import Decision, ToolCallRequest
from agentgate.policies.engine import Policy
from agentgate.security.inspection import inspect, redact


class Runtime:
    def __init__(self, settings, store, registry, policy, environment):
        self.settings, self.store, self.registry, self.policy = settings, store, registry, policy
        self.environment = environment
        # ponytail: one event-loop lock for the single-process demo; use DB-backed workers for shared deployment.
        self.lock = asyncio.Lock()
        for definition in registry.definitions():
            store.put(
                "tool_definitions",
                definition["name"] + ":" + definition["version"],
                settings.tenant_id,
                definition,
            )
        self.store.put(
            "policy_versions",
            policy.digest,
            settings.tenant_id,
            {"version": policy.version, "content_hash": policy.digest},
        )

    def reload_policy(self, path: Path):
        candidate = Policy.load(path)
        self.store.put(
            "policy_versions",
            candidate.digest,
            self.settings.tenant_id,
            {"version": candidate.version, "content_hash": candidate.digest},
        )
        self.policy = candidate
        return {"version": candidate.version, "content_hash": candidate.digest}

    def error(self, request, code, explanation, findings=None):
        return {
            "decision": "DENY",
            "decision_id": str(uuid4()),
            "request_id": request.context.request_id,
            "trace_id": request.context.trace_id,
            "tool_name": request.tool_name,
            "actor_id": request.context.actor_id,
            "tenant_id": request.context.tenant_id,
            "environment": request.context.environment,
            "matched_rule_ids": [],
            "findings": findings or [],
            "risk_score": 0,
            "explanation": explanation,
            "executed": False,
            "approval_id": None,
            "result": {
                "success": False,
                "data": None,
                "error_code": code,
                "safe_message": explanation,
            },
        }

    async def call(self, request, execute=True):
        # Never trust a caller-supplied trace identifier as a storage key.
        request = request.model_copy(deep=True)
        request.context.trace_id = uuid4().hex
        async with self.lock:
            return await self._call(request, execute=execute)

    async def _call(self, request, execute=True, approved=False):
        started = time.perf_counter()
        context = request.context
        try:
            hashed = request_hash(request, self.policy.digest)
        except (ValueError, TypeError):
            return self._record_error(
                request, "INVALID_REQUEST", "Arguments must contain finite JSON values."
            )
        key = (
            digest([context.tenant_id, context.actor_id, request.idempotency_key])
            if request.idempotency_key
            else None
        )
        if key and not approved:
            existing = self.store.idempotent_get(key)
            if existing:
                if existing["request_hash"] != hashed:
                    return self._record_error(
                        request,
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key is bound to another request.",
                    )
                if existing["data"] is not None:
                    return existing["data"]
                return self._record_error(
                    request,
                    "IDEMPOTENCY_CONFLICT",
                    "Prior execution is unresolved; do not retry a write blindly.",
                )
        self.store.append(
            context.trace_id,
            "request.received",
            {
                "tool_name": request.tool_name,
                "arguments": request.arguments,
                "actor_id": context.actor_id,
                "tenant_id": context.tenant_id,
            },
        )
        if (
            len(canonical(request.model_dump(mode="json")).encode())
            > self.settings.max_request_bytes
        ):
            return self._record_error(
                request, "INVALID_REQUEST", "Request exceeds the configured size limit."
            )
        registered = self.registry.tools.get(request.tool_name)
        if registered is None:
            return self._record_error(
                request, "UNKNOWN_TOOL", "Tool is not in the explicit registry."
            )
        tool = registered.definition
        self.store.append(
            context.trace_id, "tool.resolved", {"name": tool.name, "version": tool.version}
        )
        if not tool.enabled:
            return self._record_error(request, "DISABLED_TOOL", "Tool is disabled.")
        if not Draft202012Validator(tool.input_schema).is_valid(request.arguments):
            return self._record_error(
                request, "INVALID_REQUEST", "Arguments do not match the registered schema."
            )
        if (
            not self.environment.owns(request.arguments, context.tenant_id)
            or tool.allowed_tenants is not None
            and context.tenant_id not in tool.allowed_tenants
        ):
            return self._record_error(
                request,
                "TENANT_MISMATCH",
                "The resource does not belong to the authenticated tenant.",
            )
        findings = inspect(request.arguments) + inspect(tool.description, "tool_description")
        self.store.append(context.trace_id, "inspection.completed", {"findings": findings})
        decision, rules = self.policy.evaluate(request, tool, findings, approved=approved)
        if context.environment not in tool.allowed_environments:
            decision = Decision.DENY
        changes_write_intent = (
            tool.operation.value != "read" and redact(request.arguments) != request.arguments
        )
        if decision == Decision.REDACT_AND_CONTINUE:
            clean_request = request.model_copy(update={"arguments": redact(request.arguments)})
            remaining = inspect(clean_request.arguments) + inspect(
                tool.description, "tool_description"
            )
            # Input redaction cannot satisfy a rule on the original sensitive value.
            decision, reevaluated_rules = self.policy.evaluate(
                clean_request, tool, remaining, approved=approved
            )
            rules = list(dict.fromkeys(rules + reevaluated_rules))
            request = clean_request
            if decision == Decision.REDACT_AND_CONTINUE or not Draft202012Validator(
                tool.input_schema
            ).is_valid(request.arguments):
                decision = Decision.DENY
        if changes_write_intent:
            decision = Decision.DENY
        risk = min(
            100,
            {"low": 10, "medium": 35, "high": 65, "critical": 85}[tool.risk_level.value]
            + (10 if tool.operation.value != "read" else 0)
            + (10 if context.environment == "production" else 0)
            + (10 if findings else 0),
        )
        explanation = f"{context.actor_id} requested {tool.name} in {context.environment} for {context.tenant_id}. Rules: {', '.join(rules) or 'none'}. {decision.value}; explicit allow is required and deny takes precedence. Risk {risk}/100 is explanatory, not authorization."
        if changes_write_intent:
            explanation += " Required redaction would alter this write; a separate sensitive-data channel is needed."
        response = {
            "decision": decision.value,
            "decision_id": str(uuid4()),
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "tool_name": tool.name,
            "tool_version": tool.version,
            "actor_id": context.actor_id,
            "tenant_id": context.tenant_id,
            "environment": context.environment,
            "matched_rule_ids": rules,
            "findings": findings,
            "risk_score": risk,
            "explanation": explanation,
            "executed": False,
            "approval_id": None,
            "policy_version": self.policy.version,
            "redacted_arguments": redact(request.arguments),
            "result": {"success": False, "data": None, "error_code": None},
        }
        self.store.append(context.trace_id, "policy.evaluated", response)
        self.store.put(
            "policy_decisions",
            response["decision_id"],
            context.tenant_id,
            {**response, "request_hash": hashed},
        )
        if (
            key
            and (execute or decision == Decision.REQUIRE_HUMAN_APPROVAL)
            and not approved
            and not self.store.idempotent_reserve(key, hashed)
        ):
            return self._record_error(
                request, "IDEMPOTENCY_CONFLICT", "Another execution owns this key."
            )
        if decision == Decision.DENY:
            response["result"]["error_code"] = "POLICY_DENIED"
            response["explanation"] += " Tool server was not contacted."
        elif decision == Decision.REQUIRE_HUMAN_APPROVAL:
            approval_id = str(uuid4())
            # Persist the executable redacted request; hash both it and original intent.
            safe_request = request.model_copy(update={"arguments": redact(request.arguments)})
            approval = {
                "approval_id": approval_id,
                "decision_id": response["decision_id"],
                "request_hash": request_hash(safe_request, self.policy.digest),
                "original_request_hash": hashed,
                "policy_digest": self.policy.digest,
                "request": safe_request.model_dump(mode="json"),
                "tool_name": tool.name,
                "tool_version": tool.version,
                "actor_id": context.actor_id,
                "tenant_id": context.tenant_id,
                "expires_at": time.time() + self.settings.approval_ttl_seconds,
                "trace_id": context.trace_id,
                "risk_score": risk,
                "matched_rule_ids": rules,
                "findings": findings,
                "arguments": safe_request.arguments,
            }
            self.store.create_approval(approval)
            response.update(approval_id=approval_id, expires_at=approval["expires_at"])
            response["result"]["error_code"] = "APPROVAL_REQUIRED"
            response["explanation"] += (
                " Tool server was not contacted; an authenticated operator must consume this approval."
            )
            self.store.append(context.trace_id, "approval.created", approval)
        elif not execute:
            response["result"]["success"] = True
            response["explanation"] += " Authorization only; tool server was not contacted."
        else:
            self.store.append(context.trace_id, "tool.execution.started", {"tool_name": tool.name})
            tracer = trace.get_tracer("agentgate")
            with tracer.start_as_current_span("agentgate.tool_call") as span:
                attrs = {
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                    "agent_id": context.agent_id,
                    "actor_id": context.actor_id,
                    "tenant_id": context.tenant_id,
                    "environment": context.environment,
                    "tool_name": tool.name,
                    "tool_version": tool.version,
                    "operation": tool.operation.value,
                    "decision": decision.value,
                    "policy_version": str(self.policy.version),
                    "finding_count": len(findings),
                    "risk_score": risk,
                    "approval_required": approved,
                }
                for name, value in attrs.items():
                    span.set_attribute("agentgate." + name, value)
                for attempt in range(tool.max_retries + 1):
                    span.set_attribute("agentgate.retry_count", attempt)
                    try:
                        response["executed"] = True
                        output = await asyncio.wait_for(
                            registered.handler(request.arguments),
                            timeout=min(
                                tool.timeout_seconds, self.settings.default_timeout_seconds
                            ),
                        )
                        if len(canonical(output).encode()) > self.settings.max_response_bytes:
                            raise ValueError("Response too large")
                        if tool.output_schema and not Draft202012Validator(
                            tool.output_schema
                        ).is_valid(output):
                            raise ValueError("Output schema mismatch")
                        output_findings = inspect(output, "response")
                        response["findings"].extend(output_findings)
                        self.store.append(
                            context.trace_id,
                            "tool.response.inspected",
                            {"findings": output_findings},
                        )
                        if any(f["category"] == "prompt_injection" for f in output_findings):
                            response["result"] = {
                                "success": False,
                                "data": None,
                                "error_code": "TOOL_RESPONSE_BLOCKED",
                            }
                            self.store.append(
                                context.trace_id,
                                "tool.response.blocked",
                                {"findings": output_findings},
                            )
                        else:
                            response["result"] = {
                                "success": True,
                                "data": redact(output),
                                "error_code": None,
                            }
                        self.store.append(
                            context.trace_id,
                            "tool.execution.completed",
                            {"result": response["result"]},
                        )
                        break
                    except TimeoutError:
                        response["result"] = {
                            "success": False,
                            "data": None,
                            "error_code": "TOOL_TIMEOUT",
                        }
                    except (ValueError, TypeError):
                        response["result"] = {
                            "success": False,
                            "data": None,
                            "error_code": "TOOL_RESPONSE_BLOCKED",
                        }
                        break
                    except Exception:
                        response["result"] = {
                            "success": False,
                            "data": None,
                            "error_code": "TOOL_FAILED",
                        }
                    self.store.append(
                        context.trace_id,
                        "tool.execution.failed",
                        {"error_code": response["result"]["error_code"], "attempt": attempt + 1},
                    )
                span.set_attribute("agentgate.duration_ms", (time.perf_counter() - started) * 1000)
            response["explanation"] += " Tool server was contacted after authorization."
        response["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        response = redact(response)
        self.store.append(context.trace_id, "request.completed", response)
        self.store.put("traces", context.trace_id, context.tenant_id, response)
        if key and (execute or decision == Decision.REQUIRE_HUMAN_APPROVAL):
            self.store.idempotent_finish(key, response)
        return response

    def _record_error(self, request, code, explanation):
        response = self.error(request, code, explanation)
        self.store.append(request.context.trace_id, "request.completed", response)
        self.store.put("traces", request.context.trace_id, request.context.tenant_id, response)
        return response

    async def resolve_approval(self, identifier, context, approve):
        async with self.lock:
            approval = self.store.approval(identifier, context.tenant_id)
            fallback = ToolCallRequest(
                tool_name="approval",
                arguments={},
                context=context.model_copy(update={"trace_id": uuid4().hex}),
            )
            if approval is None:
                return self._record_error(
                    fallback, "APPROVAL_MISMATCH", "Approval not found for this identity."
                )
            request = ToolCallRequest.model_validate(approval["request"])
            registered = self.registry.tools.get(request.tool_name)
            if (
                context.environment != request.context.environment
                or context.agent_id != request.context.agent_id
                or registered is None
                or registered.definition.version != approval.get("tool_version")
            ):
                return self._record_error(
                    fallback,
                    "APPROVAL_MISMATCH",
                    "Approval environment, agent or tool version changed.",
                )
            if approval["expires_at"] <= time.time():
                self.store.append(
                    request.context.trace_id, "approval.expired", {"approval_id": identifier}
                )
                return self._record_error(
                    fallback, "APPROVAL_EXPIRED", "Approval expired; request a fresh decision."
                )
            hashed = request_hash(request, self.policy.digest)
            if not self.store.consume(identifier, context, hashed, self.policy.digest, approve):
                return self._record_error(
                    fallback,
                    "APPROVAL_MISMATCH",
                    "Approval identity, policy, hash or single-use state does not match.",
                )
            self.store.append(
                request.context.trace_id,
                "approval.approved" if approve else "approval.denied",
                {"approval_id": identifier, "approved_by": context.actor_id},
            )
            if not approve:
                return self._record_error(
                    fallback, "POLICY_DENIED", "The operator denied this request."
                )
            return await self._call(request, approved=True)
