from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentgate.api.app import create_app
from agentgate.config import Settings
from agentgate.demo import make_runtime


def client(tmp_path, **kwargs):
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path}/research.db", **kwargs)
    runtime = make_runtime(settings, initialize=True)
    return TestClient(create_app(settings, runtime))


@pytest.fixture
def analyzer(monkeypatch):
    calls = []

    async def analyze(*args, **kwargs):
        calls.append((args, kwargs))
        report = {
            "run_id": str(uuid4()),
            "repository": "octocat/Hello-World",
            "mode": kwargs.get("mode", "evidence"),
            "status": "completed",
            "summary": "Synthetic repository evidence.",
            "sources": [],
        }
        store, context = args[2:4]
        store.put("research_runs", report["run_id"], context.tenant_id, report)
        return report

    monkeypatch.setattr("agentgate.research.analyze_repository", analyze)
    return calls


def test_disabled_research_reports_config_and_rejects_runs(tmp_path, analyzer):
    with client(tmp_path, public_demo=True) as api:
        config = api.get("/api/v1/research/config")
        assert config.status_code == 200
        assert config.json()["enabled"] is False
        assert config.json()["model_available"] is False
        response = api.post(
            "/api/v1/research/runs",
            json={"repository": "octocat/Hello-World", "mode": "evidence"},
        )
        assert response.status_code == 503
    assert analyzer == []


def test_public_evidence_run_is_saved_and_listed(tmp_path, analyzer):
    with client(tmp_path, public_demo=True, research_enabled=True) as api:
        assert api.get("/api/v1/research/config").json()["enabled"] is True
        response = api.post(
            "/api/v1/research/runs",
            json={"repository": "octocat/Hello-World", "mode": "evidence"},
        )
        assert response.status_code == 200
        report = response.json()
        saved = api.get("/api/v1/research/runs/" + report["run_id"])
        assert saved.status_code == 200
        assert saved.json()["summary"] == report["summary"]
        assert any(r["run_id"] == report["run_id"] for r in api.get("/api/v1/research/runs").json())
    assert len(analyzer) == 1


def test_public_model_mode_is_forbidden_even_with_key(tmp_path, analyzer):
    with client(
        tmp_path, public_demo=True, research_enabled=True, research_api_key="private-model-key"
    ) as api:
        response = api.post(
            "/api/v1/research/runs",
            json={"repository": "octocat/Hello-World", "mode": "model"},
        )
        assert response.status_code == 403
        assert "private-model-key" not in api.get("/api/v1/research/config").text
    assert analyzer == []


def test_model_requires_administrator_and_configured_key(tmp_path, analyzer):
    with client(tmp_path, research_enabled=True, api_token="a" * 32, admin_token="b" * 32) as api:
        body = {"repository": "octocat/Hello-World", "mode": "model"}
        assert api.post("/api/v1/research/runs", json=body).status_code == 401
        assert (
            api.post(
                "/api/v1/research/runs", json=body, headers={"Authorization": "Bearer " + "a" * 32}
            ).status_code
            == 403
        )
        assert (
            api.post(
                "/api/v1/research/runs", json=body, headers={"Authorization": "Bearer " + "b" * 32}
            ).status_code
            == 503
        )
    assert analyzer == []


def test_configured_administrator_can_run_model(tmp_path, analyzer):
    with client(
        tmp_path,
        research_enabled=True,
        research_api_key="private-model-key",
        api_token="a" * 32,
        admin_token="b" * 32,
    ) as api:
        response = api.post(
            "/api/v1/research/runs",
            json={"repository": "octocat/Hello-World", "mode": "model"},
            headers={"Authorization": "Bearer " + "b" * 32},
        )
        assert response.status_code == 200
        assert "private-model-key" not in response.text
    assert len(analyzer) == 1


@pytest.mark.parametrize(
    "repository", ["", "../secret", "https://evil.example/repo", "owner", "a/b/c"]
)
def test_malformed_repository_rejected_before_network(tmp_path, analyzer, repository):
    with client(tmp_path, public_demo=True, research_enabled=True) as api:
        response = api.post(
            "/api/v1/research/runs", json={"repository": repository, "mode": "evidence"}
        )
        assert response.status_code == 422
    assert analyzer == []


def test_research_reports_are_tenant_scoped(tmp_path, analyzer):
    with client(tmp_path, dev_mode=True, research_enabled=True) as api:
        response = api.post(
            "/api/v1/research/runs",
            json={"repository": "octocat/Hello-World", "mode": "evidence"},
        )
        assert response.status_code == 200
        identifier = response.json()["run_id"]
        headers = {"X-Tenant-ID": "tenant-other"}
        assert api.get("/api/v1/research/runs/" + identifier, headers=headers).status_code == 404
        assert api.get("/api/v1/research/runs", headers=headers).json() == []
        assert api.get("/api/v1/research/runs/" + identifier).status_code == 200


def test_public_research_quota_stops_fifth_run_before_network(tmp_path, analyzer):
    with client(tmp_path, public_demo=True, research_enabled=True) as api:
        body = {"repository": "octocat/Hello-World", "mode": "evidence"}
        for _ in range(4):
            assert api.post("/api/v1/research/runs", json=body).status_code == 200
        assert api.post("/api/v1/research/runs", json=body).status_code == 429
    assert len(analyzer) == 4
