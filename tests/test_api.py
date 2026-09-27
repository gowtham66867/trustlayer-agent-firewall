import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def setup_function():
    client.post("/api/reset")


def test_health_and_seed_inbox():
    assert client.get("/api/health").json()["ok"] is True
    assert len(client.get("/api/emails").json()) == 12


def test_credential_free_demo_runs_end_to_end(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_MODE", "auto")
    response = client.post("/api/run")
    assert response.status_code == 200
    assert len(response.json()["processed"]) == 12
    assert all(item["policy"] for item in response.json()["emails"])


def test_reject_only_accepts_pending_items():
    response = client.post("/api/emails/e1/reject")
    assert response.status_code == 400


def test_auto_action_can_be_undone(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_MODE", "auto")
    client.post("/api/run")
    entry = next(item for item in client.get("/api/emails").json() if item["action_id"])
    response = client.post(f"/api/emails/{entry['email']['id']}/undo")
    assert response.status_code == 200
    assert response.json()["status"] == "undone"
    assert (
        next(item for item in client.get("/api/actions").json() if item["id"] == entry["action_id"])["undone"]
        is True
    )


def test_provider_failure_does_not_commit_partial_run(monkeypatch):
    calls = 0

    def unreliable(_email):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("provider unavailable")
        return {
            "category": "actionable_task",
            "reasoning": "A valid action before the simulated provider failure.",
            "confidence": 0.9,
            "sensitive": False,
            "proposed_action": {"type": "create_task", "task_title": "Test"},
        }

    monkeypatch.setattr(main, "analyze_email", unreliable)
    response = client.post("/api/run")
    assert response.status_code == 502
    assert all(item["status"] == "unprocessed" for item in client.get("/api/emails").json())
    assert client.get("/api/tasks").json() == []


def test_human_can_approve_and_reject_only_pending_items(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_MODE", "auto")
    client.post("/api/run")

    approved = client.post("/api/emails/e2/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert client.post("/api/emails/e2/approve").status_code == 400

    rejected = client.post("/api/emails/e4/reject")
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


def test_unknown_email_ids_return_404():
    assert client.post("/api/emails/missing/approve").status_code == 404
    assert client.post("/api/emails/missing/reject").status_code == 404
    assert client.post("/api/emails/missing/undo").status_code == 404
