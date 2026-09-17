"""SQLite evidence store. Conditional writes enforce approval and idempotency ownership."""

import time
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.pool import StaticPool

from agentgate.core.hashing import digest
from agentgate.security.inspection import redact

metadata = MetaData()
schema = Table("schema_version", metadata, Column("version", Integer, primary_key=True))
records = {}
for name in (
    "tool_definitions",
    "policy_versions",
    "policy_decisions",
    "traces",
    "harness_runs",
    "eval_runs",
    "research_runs",
):
    records[name] = Table(
        name,
        metadata,
        Column("id", String, primary_key=True),
        Column("tenant_id", String, nullable=False, index=True),
        Column("created_at", Float, nullable=False),
        Column("data", JSON, nullable=False),
    )
trace_events = Table(
    "trace_events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("trace_id", String, nullable=False, index=True),
    Column("sequence_number", Integer, nullable=False),
    Column("data", JSON, nullable=False),
    Column("event_hash", String, nullable=False),
    UniqueConstraint("trace_id", "sequence_number"),
)
trajectory_events = Table(
    "trajectory_events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("run_id", String, nullable=False, index=True),
    Column("sequence_number", Integer, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("run_id", "sequence_number"),
)
approvals = Table(
    "approvals",
    metadata,
    Column("id", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("actor_id", String, nullable=False),
    Column("status", String, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("request_hash", String, nullable=False),
    Column("policy_digest", String, nullable=False),
    Column("data", JSON, nullable=False),
)
idempotency = Table(
    "idempotency",
    metadata,
    Column("id", String, primary_key=True),
    Column("request_hash", String, nullable=False),
    Column("data", JSON),
)


class Store:
    def __init__(self, url: str, max_events: int = 200):
        if url.startswith("sqlite:///") and not url.endswith(":memory:"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False, "timeout": 10}}
        if url.endswith(":memory:"):
            kwargs["poolclass"] = StaticPool
        self.engine = create_engine(url, **kwargs)
        self.max_events = max_events

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

    def initialize(self):
        metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            if conn.execute(select(schema.c.version)).first() is None:
                conn.execute(insert(schema).values(version=1))
            for table in ("trace_events", "trajectory_events"):
                conn.execute(
                    text(
                        f"CREATE TRIGGER IF NOT EXISTS {table}_immutable BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'Evidence is append-only'); END"
                    )
                )
        self.check()

    def check(self):
        try:
            with self.engine.connect() as conn:
                versions = conn.execute(select(schema.c.version)).scalars().all()
                conn.execute(select(records["research_runs"].c.id).limit(0))
        except Exception as exc:
            raise RuntimeError(
                "Database not initialized. Run python -m agentgate.cli init-db"
            ) from exc
        if versions != [1]:
            raise RuntimeError("Unsupported schema version. Restore a compatible database.")

    def put(self, table, identifier, tenant, data):
        target = records[table]
        clean = redact(data)
        with self.engine.begin() as conn:
            if conn.execute(select(target.c.id).where(target.c.id == identifier)).first():
                conn.execute(update(target).where(target.c.id == identifier).values(data=clean))
            else:
                conn.execute(
                    insert(target).values(
                        id=identifier, tenant_id=tenant, created_at=time.time(), data=clean
                    )
                )

    def get(self, table, identifier, tenant):
        target = records[table]
        with self.engine.connect() as conn:
            return conn.execute(
                select(target.c.data).where(target.c.id == identifier, target.c.tenant_id == tenant)
            ).scalar_one_or_none()

    def list(self, table, tenant, limit=100):
        target = records[table]
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(target)
                .where(target.c.tenant_id == tenant)
                .order_by(target.c.created_at.desc())
                .limit(min(limit, 100))
            ).mappings()
            return [{**row["data"], "created_at": row["created_at"]} for row in rows]

    def append(self, trace_id, event_type, payload):
        with self.engine.begin() as conn:
            last = (
                conn.execute(
                    select(trace_events)
                    .where(trace_events.c.trace_id == trace_id)
                    .order_by(trace_events.c.sequence_number.desc())
                    .limit(1)
                )
                .mappings()
                .first()
            )
            sequence = last["sequence_number"] + 1 if last else 0
            if sequence >= self.max_events:
                raise ValueError("Trace event limit reached")
            data = {
                "sequence": sequence,
                "event_type": event_type,
                "timestamp": time.time(),
                "payload": redact(payload),
                "previous_hash": last["event_hash"] if last else "0" * 64,
            }
            hashed = digest(data)
            conn.execute(
                insert(trace_events).values(
                    trace_id=trace_id, sequence_number=sequence, data=data, event_hash=hashed
                )
            )
            return {**data, "event_hash": hashed}

    def trace(self, identifier, tenant):
        result = self.get("traces", identifier, tenant)
        if result is None:
            return None
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(trace_events)
                .where(trace_events.c.trace_id == identifier)
                .order_by(trace_events.c.sequence_number)
            ).mappings()
            return {
                **result,
                "events": [{**row["data"], "event_hash": row["event_hash"]} for row in rows],
            }

    def list_traces(self, tenant):
        return self.list("traces", tenant)

    def create_approval(self, data):
        with self.engine.begin() as conn:
            conn.execute(
                insert(approvals).values(
                    id=data["approval_id"],
                    tenant_id=data["tenant_id"],
                    actor_id=data["actor_id"],
                    status="pending",
                    expires_at=data["expires_at"],
                    request_hash=data["request_hash"],
                    policy_digest=data["policy_digest"],
                    data=redact(data),
                )
            )

    def approval(self, identifier, tenant):
        with self.engine.connect() as conn:
            row = (
                conn.execute(
                    select(approvals).where(
                        approvals.c.id == identifier, approvals.c.tenant_id == tenant
                    )
                )
                .mappings()
                .first()
            )
            if row:
                return {**row["data"], "status": row["status"]}
        return None

    def list_approvals(self, tenant):
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(approvals).where(approvals.c.tenant_id == tenant).limit(100)
            ).mappings()
            return [
                {
                    **row["data"],
                    "status": "expired"
                    if row["status"] == "pending" and row["expires_at"] <= time.time()
                    else row["status"],
                }
                for row in rows
            ]

    def consume(self, identifier, context, expected_hash, policy_digest, approve):
        with self.engine.begin() as conn:
            result = conn.execute(
                update(approvals)
                .where(
                    approvals.c.id == identifier,
                    approvals.c.tenant_id == context.tenant_id,
                    approvals.c.actor_id == context.actor_id,
                    approvals.c.status == "pending",
                    approvals.c.expires_at > time.time(),
                    approvals.c.request_hash == expected_hash,
                    approvals.c.policy_digest == policy_digest,
                )
                .values(status="consumed" if approve else "denied")
            )
            return result.rowcount == 1

    def idempotent_get(self, key):
        with self.engine.connect() as conn:
            row = (
                conn.execute(select(idempotency).where(idempotency.c.id == key)).mappings().first()
            )
            return dict(row) if row else None

    def idempotent_reserve(self, key, request_hash):
        from sqlalchemy.exc import IntegrityError

        try:
            with self.engine.begin() as conn:
                conn.execute(
                    insert(idempotency).values(id=key, request_hash=request_hash, data=None)
                )
            return True
        except IntegrityError:
            return False

    def idempotent_finish(self, key, result):
        with self.engine.begin() as conn:
            conn.execute(
                update(idempotency).where(idempotency.c.id == key).values(data=redact(result))
            )

    def persist_trajectory(self, report, tenant):
        self.put("harness_runs", report["run_id"], tenant, report)
        with self.engine.begin() as conn:
            for event_data in report["events"]:
                conn.execute(
                    insert(trajectory_events).values(
                        run_id=report["run_id"],
                        sequence_number=event_data["sequence"],
                        data=redact(event_data),
                    )
                )

    def prune(self, days):
        cutoff = time.time() - days * 86400
        with self.engine.begin() as conn:
            old = select(records["traces"].c.id).where(records["traces"].c.created_at < cutoff)
            conn.execute(delete(trace_events).where(trace_events.c.trace_id.in_(old)))
            for name in (
                "traces",
                "policy_decisions",
                "eval_runs",
                "harness_runs",
                "research_runs",
            ):
                if name == "harness_runs":
                    old_runs = select(records[name].c.id).where(records[name].c.created_at < cutoff)
                    conn.execute(
                        delete(trajectory_events).where(trajectory_events.c.run_id.in_(old_runs))
                    )
                conn.execute(delete(records[name]).where(records[name].c.created_at < cutoff))
            conn.execute(delete(approvals).where(approvals.c.expires_at < cutoff))

    def retain_latest(self, table, tenant, count):
        """Bound public synthetic evidence; local operator retention uses prune()."""
        if table not in {"traces", "harness_runs", "eval_runs", "research_runs"}:
            raise ValueError("Unsupported retention table")
        target = records[table]
        with self.engine.begin() as conn:
            old = list(
                conn.execute(
                    select(target.c.id)
                    .where(target.c.tenant_id == tenant)
                    .order_by(target.c.created_at.desc())
                    .offset(count)
                ).scalars()
            )
            if old:
                if table == "traces":
                    conn.execute(delete(trace_events).where(trace_events.c.trace_id.in_(old)))
                    decision_ids = select(target.c.data["decision_id"].as_string()).where(
                        target.c.id.in_(old)
                    )
                    conn.execute(
                        delete(records["policy_decisions"]).where(
                            records["policy_decisions"].c.tenant_id == tenant,
                            records["policy_decisions"].c.id.in_(decision_ids),
                        )
                    )
                elif table == "harness_runs":
                    conn.execute(
                        delete(trajectory_events).where(trajectory_events.c.run_id.in_(old))
                    )
                conn.execute(delete(target).where(target.c.id.in_(old)))
