# Threat model

## Scope and assets

Protect tool authority, tenant-owned resources, approval integrity, sensitive payloads, and the evidence used to explain decisions. Treat agent-generated arguments, retrieved text, tool descriptions, and tool outputs as untrusted. Trust server configuration, registered handlers, and the host running AgentGate.

The demo uses synthetic state. A production integration must ensure agents cannot directly reach the underlying privileged adapter outside this boundary.

| Threat | Implemented boundary | Residual risk |
| --- | --- | --- |
| Prompt injection in arguments or tool output | Content inspection, deny rules, blocked unsafe output | Pattern coverage is incomplete; absence of a finding is not proof of safety |
| Invented or malformed tool call | Explicit registry and JSON schema checks | A registered handler can still contain a bug |
| Cross-tenant access | Server-derived tenant and resource ownership checks | External adapters must enforce equivalent ownership semantics |
| Privilege spoofing in request JSON | API identity comes from authentication and server configuration | Host or credential compromise bypasses this assumption |
| Approval replay or request substitution | Bound request hash, policy digest, expiry, and conditional consumption | An authorized reviewer can still approve the wrong business action |
| Repeated write after timeout | Persisted idempotency and no automatic write retries | Remote effect may finish after the client observes a failure |
| Sensitive values in logs or responses | Redaction before stored evidence and returned output | Detectors do not recognize every possible secret format |
| Evidence modification | Hash-linked events and strict replay | Database owner can rewrite an entire chain without external anchoring |
| Slow or malicious handler | Size, step, and cooperative timeout limits | In-process code is not an OS security boundary |
| Public demo abuse | Synthetic isolated execution and bounded requests | Host-level quotas and edge rate limiting remain deployment concerns |

Sensitive writes fail closed when mandatory redaction would change their arguments. The runtime must not store a redaction placeholder as a customer email or other business value. Supporting real sensitive writes requires a separate secret-handling mechanism that preserves authorized intent without persisting raw secrets.

## Outside the claimed boundary

AgentGate does not provide secure arbitrary-code execution, production payment settlement, a complete DLP classifier, cryptographic identity federation, or independent evidence notarization. It does not guarantee that a remote tool can roll back a write.

## Security invariants to preserve

- No external handler invocation after deny or pending approval.
- No caller-selected actor, tenant, or privilege at the HTTP boundary.
- No successful second consumption of the same approval.
- No automatic retry of non-read side effects.
- No claim that replay executed live tools.
- No baseline harness execution against external adapters.

Tests and evaluation reports supply evidence for bounded cases. They are not a proof against every attack. See [Security policy](../SECURITY.md) for reporting a reproducible issue.
