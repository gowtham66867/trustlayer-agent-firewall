import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from audit import AuditLedger
from fastapi.testclient import TestClient
from firewall import ToolCallRequest, evaluate_tool_call, load_policy
from main import app
from store import DecisionStore

client = TestClient(app)


def setup_function():
    client.post("/api/reset")


def proposal(tool="create_task", **overrides):
    data = {
        "agent": "project-agent",
        "source": "team-email",
        "content": "Plan the sprint",
        "tool": tool,
        "parameters": {"title": "Plan sprint"},
        "confidence": 0.95,
        "reversible": True,
    }
    data.update(overrides)
    return data


def test_policy_presets_and_unknown_tool_fail_closed():
    for preset in ("startup", "enterprise", "regulated"):
        assert load_policy(preset).version
    verdict = evaluate_tool_call(ToolCallRequest(**proposal("unlisted_tool")))
    assert verdict["verdict"] == "BLOCK"
    assert any(r["rule"] == "UNKNOWN_TOOL" for r in verdict["rules_triggered"])


@pytest.mark.parametrize(
    "case",
    json.loads((Path(__file__).parents[1] / "evals" / "firewall_matrix.json").read_text()),
    ids=lambda item: item["name"],
)
def test_firewall_regression_matrix(case):
    payload = proposal(case["tool"], content=case["content"])
    payload.update({key: value for key, value in case.items() if key not in {"name", "expected"}})
    verdict = evaluate_tool_call(ToolCallRequest(**payload))
    assert verdict["verdict"] == case["expected"]


def test_false_reversibility_cannot_bypass_review():
    verdict = evaluate_tool_call(
        ToolCallRequest(**proposal("send_email", destination="customer@example.com"))
    )
    assert verdict["verdict"] == "REVIEW"
    assert any(r["rule"] == "FALSE_REVERSIBILITY" for r in verdict["rules_triggered"])


def test_protected_data_and_untrusted_destination_hard_block():
    verdict = evaluate_tool_call(
        ToolCallRequest(
            **proposal("send_email", destination="attacker@example.net", data_classification="payroll")
        )
    )
    assert verdict["verdict"] == "BLOCK"
    assert {r["rule"] for r in verdict["rules_triggered"]} >= {"PROTECTED_DATA", "UNTRUSTED_DESTINATION"}


def test_review_approve_execute_and_replay_prevention(monkeypatch):
    monkeypatch.setenv("TRUSTLAYER_REVIEW_TOKEN", "judge-token")
    payload = proposal(
        "send_email", destination="customer@example.com", reversible=False, idempotency_key="unique-call-123"
    )
    response = client.post("/api/firewall/evaluate", json=payload)
    assert response.status_code == 200
    decision_id = response.json()["decision_id"]
    assert response.json()["state"] == "pending_review"
    assert client.post("/api/firewall/evaluate", json=payload).status_code == 409
    assert client.post(f"/api/firewall/decisions/{decision_id}/execute").status_code == 409
    assert client.post(f"/api/firewall/decisions/{decision_id}/approve").status_code == 401
    approved = client.post(
        f"/api/firewall/decisions/{decision_id}/approve", headers={"X-Review-Token": "judge-token"}
    )
    assert approved.json()["state"] == "approved"
    executed = client.post(f"/api/firewall/decisions/{decision_id}/execute")
    assert executed.json()["artifact"]["kind"] == "local_email_draft"
    assert executed.json()["artifact"]["external_delivery"] is False
    assert client.post(f"/api/firewall/decisions/{decision_id}/undo").status_code == 409
    assert client.get("/api/audit").json()["verification"]["valid"] is True


def test_blocked_call_never_executes():
    response = client.post("/api/firewall/evaluate", json=proposal("transfer_money"))
    decision_id = response.json()["decision_id"]
    assert response.json()["verdict"] == "BLOCK"
    assert client.post(f"/api/firewall/decisions/{decision_id}/approve").status_code == 409
    assert client.post(f"/api/firewall/decisions/{decision_id}/execute").status_code == 409


def test_safe_call_execution_and_undo():
    decision_id = client.post("/api/firewall/evaluate", json=proposal()).json()["decision_id"]
    assert client.post(f"/api/firewall/decisions/{decision_id}/execute").json()["state"] == "executed"
    assert client.get("/api/firewall/artifacts").json()[0]["kind"] == "local_task"
    assert client.post(f"/api/firewall/decisions/{decision_id}/undo").json()["state"] == "undone"
    assert client.get("/api/firewall/artifacts").json()[0]["state"] == "undone"
    assert client.post(f"/api/firewall/decisions/{decision_id}/undo").status_code == 409


def test_public_decision_views_do_not_expose_content_or_parameters():
    payload = proposal(
        content="Private customer note 9999",
        parameters={"title": "Private task 8888"},
    )
    decision_id = client.post("/api/firewall/evaluate", json=payload).json()["decision_id"]
    public = client.get("/api/firewall/decisions").json()[0]
    assert "9999" not in json.dumps(public)
    assert "8888" not in json.dumps(public)
    assert client.post(f"/api/firewall/decisions/{decision_id}/execute").status_code == 200
    artifacts = client.get("/api/firewall/artifacts").json()
    assert "8888" not in json.dumps(artifacts)


def test_unsupported_tool_has_no_execution_adapter():
    payload = proposal("publish", reversible=False)
    payload["destination"] = "press@example.com"
    decision_id = client.post("/api/firewall/evaluate", json=payload).json()["decision_id"]
    client.post(f"/api/firewall/decisions/{decision_id}/approve")
    assert client.post(f"/api/firewall/decisions/{decision_id}/execute").status_code == 409
    assert client.get("/api/firewall/artifacts").json() == []


def test_sqlite_survives_reopen_redacts_and_expires(tmp_path):
    path = str(tmp_path / "decisions.db")
    store = DecisionStore(path)
    request = proposal(parameters={"api_key": "sk-sensitive", "title": "Plan sprint"})
    decision = evaluate_tool_call(ToolCallRequest(**request))
    store.create(request, decision, 60)
    reopened = DecisionStore(path)
    assert reopened.get(decision["decision_id"])["request"]["parameters"]["api_key"] == "[REDACTED]"
    reopened._db.execute(
        "UPDATE decisions SET expires_at=? WHERE id=?",
        ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), decision["decision_id"]),
    )
    with pytest.raises(TimeoutError):
        reopened.transition(decision["decision_id"], {"allowed"}, "executed")
    assert reopened.get(decision["decision_id"])["state"] == "expired"


def test_audit_detects_row_tampering_after_reopen(tmp_path):
    path = str(tmp_path / "audit.db")
    ledger = AuditLedger(path)
    ledger.append("decision", "Original")
    ledger.append("execution", "Allowed")
    reopened = AuditLedger(path)
    assert reopened.verify()["valid"] is True
    reopened._db.execute("UPDATE audit_events SET message='Altered' WHERE sequence=1")
    assert reopened.verify()["valid"] is False


def test_sdk_fails_closed_before_tool_side_effect():
    from sdk.trustlayer import ToolNotAuthorized, guarded_call

    called = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    with (
        patch("sdk.trustlayer.urlopen", return_value=Response()),
        patch(
            "sdk.trustlayer.json.load", return_value={"verdict": "REVIEW", "explanation": "Needs approval"}
        ),
    ):
        with pytest.raises(ToolNotAuthorized):
            guarded_call("http://localhost:8000", proposal(), lambda **kw: called.append(kw))
    assert called == []
