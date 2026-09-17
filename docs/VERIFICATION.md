# Verification record

Verified locally on 2026-09-15 with Python 3.12.13 on macOS arm64.
This covers the synthetic reference implementation and a bounded live public-data integration, not a production certification.

| Check | Observed result |
| --- | --- |
| pytest, collected under coverage | 116 passed |
| Ruff lint | Passed |
| Ruff formatting | All Python files formatted |
| mypy agentgate | Passed, 33 source files |
| Statement coverage, agentgate/evals/demo | 83.64% |
| Deterministic evaluations | 70/70 passed; 70 baseline and 70 protected trajectories |
| Independent hard safety graders | Zero unauthorized execution, approval bypass, approval replay success, tenant isolation, secret/PII persistence and unexpected-effect failures |
| Dependency audit | No known vulnerabilities in 30 locked runtime dependencies at check time |
| Python wheel build | Passed; policy, dashboard and dataset included |
| Packaged runtime outside repository | Policy loaded successfully; regression covers default dataset outside working directory |
| Chrome UI | Six views at 1440x1000 and 390x844; no document overflow or JavaScript errors |
| Repository research UI | Seventh view verified against saved live report on desktop/mobile; actual eight-event runtime trace opened; zero JavaScript errors |
| Live GitHub/OSV | Nine sources, two exact dependency versions checked, advisory records returned; 9 HTTP requests, 72,835 bytes, 4.38 seconds |
| Gemini manual tool calls | Offline transport tests verify schema, tool execution, thought-signature preservation, citation validation, and key isolation; live provider call not run because personal key is absent |
| Live HTTP smoke | Health, four demos, paired refund harness, strict replay and evaluation passed |
| Docker image execution | Not verified: Docker is not installed on this host |
| Remote GitHub CI | Not run before this local verification |
| Public hosting | Not deployed before this local verification |

## Reproduce

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy agentgate
python -m coverage run --source=agentgate,evals,demo -m pytest -q
python -m evals.run --dataset evals/cases.jsonl --mode both --output evals/reports/latest.json
python -m agentgate.harness.runner --task refund-approval --mode compare --seed 42 --report evals/reports/comparison.json
python -m agentgate.harness.replay --run-id <run-id-from-comparison> --strict
```

The source includes dependency lockfiles. The test transport emits one upstream
Starlette/AnyIO deprecation warning; it is not suppressed and does not fail tests.
Dependency advisory scans require network access; default tests and evaluations do not.

## What review caught

Regression tests cover duplicate authorization approvals bypassing idempotency,
missing environment/agent approval binding, altered write intent after redaction,
trace time filtering, numeric PII, common camelCase credential keys, replay summary
tampering, and policy failures that otherwise undercount unauthorized execution.
A policy-mutation test forces ALLOW and checks that independent safety graders fail.

Research checks cover repository/tenant forgery, redirects, inherited credentials, bounded responses,
injected issue content, npm aliases, incomplete or malformed OSV results, model citations, administrator-only
model access, and public quotas. Test settings ignore local dotenv files; public trace retention also
removes the associated decision records.

The [saved live report](research-live-example.json) analyzes the educational repository
`Google-DSC-DMCE/Vulnerable-Flask-App` at commit `3af74de2b5473fa2e6e84e65b8f83511fa630acf`.
It queried `Flask==2.0.1` and `mysql-connector-python==8.0.26`. Advisory identifiers can overlap
across databases, so the report does not equate returned record count with unique vulnerabilities.

## Deliberate release limits

- Public mode offers resettable synthetic tools and opt-in bounded public GitHub/OSV reads. Operator mutation and hosted-model endpoints remain unavailable to public users.
- The one-process SQLite design is not a shared multi-tenant hosted product.
- In-process fake tools are trusted code. Network/subprocess adapters are not admitted to the harness; arbitrary-code isolation needs OS controls.
- Regex inspection is incomplete. Synthetic precision/recall cannot predict real-world attack detection.
- Sensitive writes are denied when mandatory redaction would alter their intent. Real contact updates need a separate sensitive-data execution channel.
- Local hash chains detect inconsistent edits, not a complete malicious rewrite or deletion by a database owner.
- Generic HTTP and optional MCP adapters have contract tests. The dedicated GitHub/OSV research integration additionally has live evidence; no arbitrary external tool server is connected.
- Async cancellation needs cooperative tool handlers. Synchronous handlers are rejected; writes are never automatically retried.
- The safe prototype rejects raw-debug logging rather than persisting sensitive payloads.
- SQLAlchemy tables store validated JSON envelopes with indexed identity/keys; this is the documented compact equivalent of the specification's wider column layout.

See [latest measured report](../evals/reports/latest.json), [real screenshots](images/overview.png),
and [deployment steps](DEPLOYMENT.md).
