# Architecture

AgentGate places one explicit execution boundary between an agent's proposed tool call and a registered async handler. One Python service owns the API, dashboard, policy runtime, and local SQLite evidence store.

## Components

| Component | Responsibility |
| --- | --- |
| `agentgate/api` | Construct trusted identity from configuration and credentials; expose bounded endpoints |
| `agentgate/core` | Pydantic contracts and canonical hashing |
| `agentgate/registry` | Explicit tool definitions, JSON schemas, handlers, and execution limits |
| `agentgate/security` | Inspect and redact inputs, metadata, outputs, and stored evidence |
| `agentgate/policies` | Evaluate versioned YAML rules with deny precedence |
| `agentgate/runtime` | Gate execution, consume approvals, enforce idempotency and timeouts |
| `agentgate/storage` | SQLite persistence, approval transitions, and hash-linked events |
| `agentgate/harness` | Seeded fake environments, trajectories, graders, and offline replay |
| `agentgate/dashboard` | Vanilla HTML, CSS, and JavaScript reading the API |
| `evals` | Repeatable dataset evaluation and report generation |

## Request flow

1. The API derives actor, tenant, environment, and privilege from server-controlled configuration and authentication.
2. The runtime allocates its own trace identifier, resolves the registered tool, and validates arguments and tenant ownership.
3. Inspection produces findings. The policy evaluates applicable rules; absence of an explicit allow fails closed.
4. Redaction requires re-inspection and policy evaluation. A changed argument must still satisfy the tool schema. If mandatory redaction would alter write intent, the write is denied; placeholders such as `[REDACTED]` must never become customer data. Real sensitive writes require a separate secret-handling design.
5. Denied and pending requests do not call the handler. Approval binds the executable request, original intent, actor, tenant, policy digest, and expiry.
6. An allowed handler runs with a bounded timeout. Output is checked and redacted before it leaves the runtime.
7. Redacted decision and outcome evidence is persisted. An execution error remains distinct from a policy denial.

## Storage and concurrency

SQLite keeps the service easy to run and inspect. A runtime lock serializes calls, while conditional database updates prevent duplicate approval consumption. Persisted idempotency state distinguishes completed results from unresolved writes. If a process crashes after an external side effect, a local database cannot prove whether the external write completed: reconcile the provider before trying again.

Use one Uvicorn worker for this release. Multi-instance service operation, per-tenant locks, durable remote storage, and external adapters require further design and validation.

## Evidence boundary

Hash links detect changes to saved event order or payloads relative to the stored chain. They are not a signature or an independently witnessed log: an attacker with full database write access could replace the chain. Retain trusted copies externally if that is required.

## Deliberate tradeoffs

- Vanilla JavaScript avoids a frontend build system; the dashboard uses `textContent` for untrusted strings.
- A deterministic fake environment makes comparisons reproducible without model credentials or live financial effects.
- Pattern-based inspection is inspectable but incomplete. Policy and capability restrictions remain necessary even when no pattern matches.
- Python cancellation bounds cooperative async tools. It does not isolate arbitrary code, stop blocking native code, or undo remote side effects.
