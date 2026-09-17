import pytest
from sqlalchemy import text

from agentgate.storage.database import Store


def test_schema_initialization_is_explicit_and_evidence_is_immutable(tmp_path):
    store = Store(f"sqlite:///{tmp_path}/db.sqlite")
    with pytest.raises(RuntimeError, match="init-db"):
        store.check()
    store.initialize()
    store.append("trace-1", "request.received", {"safe": True})
    with pytest.raises(Exception, match="append-only"):
        with store.engine.begin() as connection:
            connection.execute(text("UPDATE trace_events SET event_hash='changed'"))
    store.engine.dispose()


def test_public_retention_bounds_parent_and_child_records(tmp_path):
    store = Store(f"sqlite:///{tmp_path}/db.sqlite")
    store.initialize()
    for i in range(4):
        store.put(
            "traces",
            f"trace-{i}",
            "tenant-demo",
            {"trace_id": f"trace-{i}", "decision_id": f"decision-{i}"},
        )
        store.put("policy_decisions", f"decision-{i}", "tenant-demo", {"id": f"decision-{i}"})
        store.append(f"trace-{i}", "request.received", {})
    store.retain_latest("traces", "tenant-demo", 2)
    assert len(store.list_traces("tenant-demo")) == 2
    assert store.trace("trace-0", "tenant-demo") is None
    assert len(store.list("policy_decisions", "tenant-demo")) == 2
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM trace_events")).scalar_one() == 2


def test_existing_unknown_schema_is_not_changed_by_init(tmp_path):
    store = Store(f"sqlite:///{tmp_path}/db.sqlite")
    store.initialize()
    with store.engine.begin() as connection:
        connection.execute(text("UPDATE schema_version SET version=99"))
    with pytest.raises(RuntimeError, match="Unsupported"):
        store.initialize()
