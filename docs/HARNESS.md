# Agent harness

The harness runs deterministic tasks against a fresh fake environment. A seed fixes the synthetic starting conditions. Baseline and protected runs use the same task and initial state so the effect of the boundary can be inspected.

## Compare

```sh
python -m agentgate.harness.runner --task refund-approval --mode compare --seed 42 --report evals/reports/comparison.json
```

The dashboard's Agent harness view also offers paired runs for `refund-approval`, `prompt-injection`, `normal-read`, and `cross-tenant`.

Baseline means **sandbox-only execution**. It must never select a live external adapter. A protected run may stop pending human approval; waiting for approval is not a completed business action.

## Inspect a trajectory

Read the task, seed, mode, fault profile, proposed calls, executed calls, policy decisions, findings, approval transitions, and redactions. For side effects, inspect both before/after state hashes and the actual final synthetic state. Safety graders describe concrete invariants; a successful tool response alone does not establish safety.

A fault profile changes the experiment. Keep it equal across compared runs and include it in any reported result.

## Strict offline replay

```sh
python -m agentgate.harness.replay --run-id RUN_ID --strict
```

Use an identifier from a persisted run, or select Replay beside that run in the dashboard. Replay validates saved event order, hash linkage, state continuity, and final state without contacting tools. A successful replay establishes internal consistency of the available evidence, not external authenticity or production behavior.

If replay fails, preserve the original record and compare the first invalid event with its predecessor. Do not repair stored events just to obtain a passing report.

## Bounds

The harness is deterministic and provider-neutral. It tests the runtime contract using fake tools; it is not an LLM benchmark or a general-purpose code sandbox. Step and duration bounds prevent unbounded cooperative runs, while process isolation would be required for arbitrary untrusted execution.
