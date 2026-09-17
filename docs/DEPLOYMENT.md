# Deployment

**Status: prepared, not published.** These files do not establish that an image was built, a remote workflow passed, or a public service is live.

## Local container rehearsal

```sh
docker compose up --build
```

Open [localhost:7860](http://localhost:7860). Compose binds the port to loopback and persists SQLite in a named volume. The image runs as UID 1000, initializes the database, and starts one Uvicorn worker on port 7860. `/app/data` is writable by that user.

If `requirements.lock` is present, the image installs it before the project. Keep the lock synchronized with project dependencies. Review dependency audit results before publishing a release.

## Docker web service

1. Publish the reviewed repository contents, including the root Dockerfile and README metadata.
2. Keep `AGENTGATE_ENV=production`, `AGENTGATE_PUBLIC_DEMO=true`, and `AGENTGATE_DEV_MODE=false`.
3. Set `AGENTGATE_ALLOWED_HOSTS` to a JSON list including the deployed hostname.
4. Confirm the build log, health endpoint, dashboard, all four demo scenarios, a harness comparison, replay, and evaluation behavior from the deployed URL.
5. Record the source revision and actual result. Publish the URL only after these checks succeed.

Free hosting is a demonstration tier: it can sleep and its local filesystem may be reset. Treat stored runs as ephemeral unless the host provides and you configure persistence. Export evidence you need to keep. Do not connect real customer systems or payment tools to this public demo.

## Optional static evidence

GitHub Pages can host exported documentation and measured reports. It cannot run this FastAPI service or SQLite-backed dashboard by itself. Prepare static evidence only after removing secrets and private payloads; no Pages publication is performed by this repository setup.

## Release and rollback

Before release, run `make check`, `make test`, `make eval`, and `make harness`, inspect audit findings, and rehearse the container. Back up persistent data before replacing a running operator instance. Roll back to a previously verified image and compatible database backup when startup or runtime invariants fail. Do not point an older image at a changed database without verifying compatibility.
