# Public repository research

The **Repository research** view collects live public GitHub evidence and checks a bounded sample of exact dependency versions against OSV. Every repository tool call uses AgentGate's argument validation, policy, output inspection, redaction, and trace storage. The existing synthetic harness remains network-free.

## Enable evidence mode

Set `AGENTGATE_RESEARCH_ENABLED=true` in your local `.env`, then run:

```sh
python -m agentgate.cli init-db
make serve
```

Open [Repository research](http://localhost:7860/#research), enter a public `owner/repository`, and select **Evidence only**. This mode needs no GitHub account, model key, or local model. It performs real external requests from the server; the dashboard can still run on your machine.

An existing installation must run `init-db` once to create the research report table. Startup checks report a missing table instead of silently modifying the database.

## Optional hosted model

Use authenticated operator mode with distinct agent/admin tokens, and configure your personal provider key as `AGENTGATE_RESEARCH_API_KEY`. `AGENTGATE_RESEARCH_MODEL` selects the Gemini model. Apply the administrator token through the dashboard's **Operator access** control, then select model mode.

The key stays on the server. Public demo users and agent-role credentials cannot invoke the hosted model. No connected GitHub account, environment GitHub token, or local repository credential is used. Only explicitly configured research credentials authorize model requests.

Model output is labeled **unverified**. Inspect its cited evidence and runtime calls; a plausible narrative is not proof of repository quality or security. A missing key does not trigger a fake model fallback.

## Interpret the report

- Repository files are read at the recorded commit. Activity endpoints are timestamped samples and can change independently.
- Supported exact pins are sampled, with at most 20 dependency versions checked. Unsupported formats, version ranges, oversized files, and failed requests are omissions, not successful scans.
- OSV results apply to the queried package versions. No returned advisory does not establish that a project is secure; the analyzer does not execute code or assess exploitability.
- Each tool result has a trace. Sources record their origin and fetch time. Read limitations before interpreting the summary.
- Source hashes cover canonical upstream JSON before projection and redaction; they cannot be recomputed from the shortened source alone. Trace hashes cover the retained redacted events.
- Public mode permits four research submissions per hour per process and retains 20 reports. Provider limits may be stricter; restarting the app does not reset an upstream quota.

For a realistic exercise, analyze a deliberately vulnerable educational repository and inspect the dependency findings. Do not execute that repository to use this feature.

## API

```sh
curl http://localhost:7860/api/v1/research/config
curl -X POST http://localhost:7860/api/v1/research/runs \
  -H 'Content-Type: application/json' \
  -d '{"repository":"Google-DSC-DMCE/Vulnerable-Flask-App","mode":"evidence"}'
curl http://localhost:7860/api/v1/research/runs
```

Use the returned `run_id` at `/api/v1/research/runs/{run_id}` for the saved report. Operator deployments require the appropriate bearer credential.

## Upstream contracts

The implementation uses the official [GitHub repository contents API](https://docs.github.com/en/rest/repos/contents), [OSV query API](https://google.github.io/osv.dev/post-v1-query/), and optional [Gemini generateContent API](https://ai.google.dev/api/generate-content). Unauthenticated GitHub requests have a [shared IP-based rate limit](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api). Hosted-model availability and free quotas depend on your personal provider account.
