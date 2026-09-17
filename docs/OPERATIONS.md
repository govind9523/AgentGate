# Operations

## Modes

| Mode | Configuration | Intended access |
| --- | --- | --- |
| Public demo | `AGENTGATE_PUBLIC_DEMO=true`, `AGENTGATE_DEV_MODE=false` | Read-only operator data; bounded isolated scenario, evaluation, and harness runs |
| Local development | `AGENTGATE_ENV=development`, `AGENTGATE_DEV_MODE=true` | Loopback-only development identity |
| Operator | `AGENTGATE_PUBLIC_DEMO=false`, `AGENTGATE_DEV_MODE=false` | Authenticated agent and administrator requests |

Production rejects development identity. `make dev` explicitly changes both environment and identity mode for local work.

## Public demo limits

Public mode caps mutations at 30 per minute, harness runs at 60 per hour, and evaluation and research submissions at 4 each per hour. Scenario runs retain up to 100 traces; research runs retain up to 200 shared traces, 20 research reports, 20 harness runs, and 2 evaluation reports. A later scenario can evict older research traces; reports retain their call summaries. These bounded demo records are not a durable audit archive; export evidence you need to retain.

Live research is opt-in (`AGENTGATE_RESEARCH_ENABLED=true`). It uses public GitHub and OSV endpoints without GitHub credentials. Hosted-model calls additionally require a configured personal research key and administrator access; public demo mode never exposes that spending capability. See [Repository research](RESEARCH.md).

## Operator credentials

Generate two distinct random secrets:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48)); print(secrets.token_urlsafe(48))"
```

Set them as `AGENTGATE_API_TOKEN` and `AGENTGATE_ADMIN_TOKEN` using the host's secret mechanism. Each must contain at least 32 characters. Do not paste them into documentation, commits, URLs, or browser storage. The dashboard's Operator access field keeps a token in page memory and clears the input after applying it. Use TLS when accessing the service beyond loopback.

Identity comes from server configuration: `AGENTGATE_ACTOR_ID`, `AGENTGATE_TENANT_ID`, and `AGENTGATE_ENV`. Do not treat user-supplied JSON as authority.

## Database lifecycle

```sh
python -m agentgate.cli init-db
python -m agentgate.cli check
python -m agentgate.cli prune
```

The default database is `data/agentgate.db`; Docker uses `/app/data/agentgate.db`. `AGENTGATE_RETENTION_DAYS` controls pruning and defaults to 30. Run pruning deliberately as part of operations; these instructions do not configure a recurring job.

Stop the service before copying its SQLite database for a simple consistent backup. Preserve the full database and any journal files when investigating a crash. Test restoration on a separate copy before replacing active data. Do not delete the database to resolve an unknown write outcome.

## Configuration

See [.env.example](../.env.example). `AGENTGATE_ALLOWED_HOSTS` is a JSON list of accepted HTTP hostnames. Add the exact deployed hostname for custom domains; do not broaden it to `*` merely to suppress a host error. Request, response, trace-event, step, and runtime limits are bounded in `Settings`.

`AGENTGATE_OTEL_ENABLED=true` enables the supported telemetry path; this release's configured exporter is console. Raw sensitive debug logging is rejected. Logs and spans complement stored traces; they do not replace approval or idempotency records.

## Recovery

- **Unauthorized:** check mode and the credential role; rotate a compromised token rather than weakening authentication.
- **Invalid host:** compare the requested hostname with `AGENTGATE_ALLOWED_HOSTS`.
- **Database check fails:** preserve the file, stop mutations, and restore a verified backup or investigate schema mismatch.
- **Write timed out or process crashed:** inspect trace/idempotency evidence and reconcile the external system before retrying.
- **Approval expired or policy changed:** create and review a new request; do not modify the old approval.

Run one Uvicorn worker. This release does not claim multi-instance SQLite coordination or high-availability operation.
