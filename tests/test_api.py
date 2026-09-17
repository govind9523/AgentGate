import pytest
from fastapi.testclient import TestClient

from agentgate.api.app import create_app
from agentgate.config import Settings
from agentgate.demo import make_runtime


def client(tmp_path, **kwargs):
    settings = Settings(
        _env_file=None, database_url=f"sqlite:///{tmp_path}/api.db", otel_enabled=False, **kwargs
    )
    runtime = make_runtime(settings, initialize=True)
    return TestClient(create_app(settings, runtime))


def test_health_and_dashboard(tmp_path):
    with client(tmp_path, public_demo=True) as api:
        assert api.get("/healthz").json()["database"] == "ok"
        assert "AgentGate" in api.get("/").text
        assert api.get("/static/app.js").status_code == 200
        assert api.get("/").headers["content-security-policy"]


def test_public_demo_cannot_mutate_operator_state(tmp_path):
    with client(tmp_path, public_demo=True) as api:
        result = api.post(
            "/api/v1/tool-calls",
            json={"tool_name": "read_orders", "arguments": {"user_id": "u-100"}},
        )
        assert result.status_code == 403
        assert api.post("/api/v1/admin/policy/reload").status_code == 403
        assert api.post("/api/v1/approvals/fake/approve").status_code == 403
        demo = api.post("/api/v1/demo/normal-read")
        assert demo.status_code == 200
        assert demo.json()["executed"] is True


def test_bearer_auth_and_body_identity_forgery(tmp_path):
    with client(tmp_path, api_token="a" * 32, admin_token="b" * 32) as api:
        body = {"tool_name": "read_orders", "arguments": {"user_id": "u-100"}}
        assert api.post("/api/v1/tool-calls", json=body).status_code == 401
        good = api.post(
            "/api/v1/tool-calls",
            json=body,
            headers={"Authorization": "Bearer " + "a" * 32, "X-Tenant-ID": "tenant-other"},
        )
        assert good.status_code == 200
        assert good.json()["tenant_id"] == "tenant-demo"
        body["context"] = {"actor_id": "admin", "tenant_id": "tenant-other"}
        assert (
            api.post(
                "/api/v1/tool-calls", json=body, headers={"Authorization": "Bearer " + "a" * 32}
            ).status_code
            == 422
        )
        assert (
            api.get(
                "/api/v1/approvals", headers={"Authorization": "Bearer " + "a" * 32}
            ).status_code
            == 403
        )


def test_admin_approval_flow(tmp_path):
    with client(tmp_path, api_token="a" * 32, admin_token="b" * 32) as api:
        held = api.post(
            "/api/v1/tool-calls",
            json={
                "tool_name": "refund_payment",
                "arguments": {"user_id": "u-100", "amount": 5000, "currency": "USD"},
            },
            headers={"Authorization": "Bearer " + "a" * 32},
        )
        assert held.status_code == 202
        path = "/api/v1/approvals/" + held.json()["approval_id"] + "/approve"
        assert api.post(path, headers={"Authorization": "Bearer " + "a" * 32}).status_code == 403
        assert api.post(path, headers={"Authorization": "Bearer " + "b" * 32}).status_code == 200
        assert api.post(path, headers={"Authorization": "Bearer " + "b" * 32}).status_code == 403


def test_request_limit_and_no_raw_validation_errors(tmp_path):
    with client(tmp_path, dev_mode=True) as api:
        assert api.post("/api/v1/tool-calls", content="x" * 70000).status_code == 413
        response = api.post(
            "/api/v1/tool-calls",
            json={"tool_name": "x", "arguments": {"password": "never-echo-me"}},
        )
        assert response.status_code == 422
        assert "never-echo-me" not in response.text
        assert (
            api.post(
                "/api/v1/demo/normal-read", headers={"Origin": "https://evil.example"}
            ).status_code
            == 403
        )


def test_bad_production_config():
    with pytest.raises(ValueError):
        Settings(_env_file=None, env="production", dev_mode=True)


def test_trace_time_filters(tmp_path):
    import time

    with client(tmp_path, public_demo=True) as api:
        before = time.time() - 1
        result = api.post("/api/v1/demo/normal-read").json()
        traces = api.get("/api/v1/traces", params={"from": before}).json()
        assert any(t["trace_id"] == result["trace_id"] for t in traces)
        assert api.get("/api/v1/traces", params={"to": before}).json() == []


def test_public_harness_persistence_and_replay(tmp_path):
    with client(tmp_path, public_demo=True) as api:
        response = api.post(
            "/api/v1/harness/runs",
            json={"task_id": "refund-approval", "mode": "protected", "seed": 42},
        )
        assert response.status_code == 200
        report = response.json()
        assert report["metrics"]["side_effects"] == 0
        saved = api.get("/api/v1/harness/runs/" + report["run_id"]).json()
        assert saved["trajectory_hash"] == report["trajectory_hash"]
        assert api.post("/api/v1/harness/runs/" + report["run_id"] + "/replay").json()["valid"]


def test_evaluation_summary_survives_persistence(tmp_path):
    with client(tmp_path, public_demo=True) as api:
        response = api.post("/api/v1/evals/runs")
        assert response.status_code == 200
        report = response.json()
        assert report["metrics"]["failed_cases"] == 0
        saved = api.get("/api/v1/evals/runs/" + report["run_id"]).json()
        assert saved["metrics"]["secret_persistence_count"] == 0
        assert saved["metrics"] == report["metrics"]
