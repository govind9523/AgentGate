# Presenting AgentGate

## Resume bullet

Built AgentGate, a Python/FastAPI control plane for agent tool calls with default-deny policies, single-use approvals, redacted audit trails and replayable evaluations; verified 116 automated tests and 70 deterministic baseline/protected scenarios.

Integrated public GitHub and OSV tools for commit-linked repository evidence and bounded dependency checks, with traceable policy decisions and administrator-only hosted-model access.

The evaluation scenarios are synthetic; the repository research example uses live public APIs. Do not describe the project as serving
production customers or quote fixture detection metrics as general security guarantees.

## Three-minute walkthrough

1. Explain the problem: an agent proposes actions; trusted application code must decide whether they are permitted.
2. Run a routine read. Open the trace to show schema, tenant and policy checks.
3. Run a high-value refund. Show that approval is required before execution.
4. Compare the refund task in the harness: same plan and initial state, one baseline effect and zero protected effects.
5. Run replay, then show a regression test that rejects changed approval arguments or a modified trajectory.
6. Open Repository research and show the saved live report: two pinned dependencies, advisory source links, and the corresponding runtime traces.
7. End with the limits: synthetic harness, bounded public-data samples, one process, heuristic inspection, and no general-purpose sandbox guarantee. Hosted-model transport is tested offline; a personal provider key is still needed for live model verification.

## Engineering decisions to explain

- Why deny has precedence over allow.
- Why consuming an approval happens before the side effect.
- Why an unresolved idempotency key cannot simply be retried after a crash.
- Why independent expected outcomes are needed to catch an authorization engine that incorrectly says ALLOW.
- Why a free public demo must not expose real operator credentials or customer systems.
- Why SQLite and vanilla JavaScript fit this workload, and when a shared database or different UI stack would be justified.
