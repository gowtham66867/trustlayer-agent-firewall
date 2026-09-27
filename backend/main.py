import os
import threading
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

load_dotenv(Path(__file__).parent / ".env")

from agent import analyze_email  # noqa: E402
from data import SEED_EMAILS  # noqa: E402
from policy import assess_policy  # noqa: E402

app = FastAPI(title="Inbox Zero Agent")

# in-memory state: email_id -> {email, analysis, status}
STATE = {
    e["id"]: {"email": e, "analysis": None, "policy": None, "status": "unprocessed", "action_id": None}
    for e in SEED_EMAILS
}
TASKS = []
EVENTS = []
LOG = []
ACTIONS = []
RUN_LOCK = threading.Lock()


def log_event(message: str):
    LOG.append(message)


def execute_reversible_action(email_id: str, analysis: dict, actor: str = "agent"):
    action = analysis.get("proposed_action", {})
    action_type = action.get("type")
    action_id = str(uuid4())
    record = {
        "id": action_id,
        "email_id": email_id,
        "type": action_type,
        "actor": actor,
        "undone": False,
    }
    log_prefix = "auto" if actor == "agent" else "human-approved"
    if action_type == "create_task":
        TASKS.append(
            {
                "action_id": action_id,
                "email_id": email_id,
                "title": action.get("task_title", "Untitled task"),
                "due": action.get("task_due", ""),
            }
        )
        log_event(f"[{log_prefix}] Created task '{action.get('task_title')}' from {email_id}")
    elif action_type == "create_calendar_event":
        EVENTS.append(
            {
                "action_id": action_id,
                "email_id": email_id,
                "title": action.get("event_title", "Untitled event"),
                "time": action.get("event_time", ""),
            }
        )
        log_event(f"[{log_prefix}] Created calendar event '{action.get('event_title')}' from {email_id}")
    elif action_type == "none":
        log_event(f"[{log_prefix}] Archived {email_id}")
    else:
        return None
    ACTIONS.append(record)
    return action_id


def undo_action(entry: dict):
    action_id = entry.get("action_id")
    if not action_id:
        return False
    record = next((item for item in ACTIONS if item["id"] == action_id and not item["undone"]), None)
    if not record:
        return False
    TASKS[:] = [item for item in TASKS if item.get("action_id") != action_id]
    EVENTS[:] = [item for item in EVENTS if item.get("action_id") != action_id]
    record["undone"] = True
    entry["status"] = "undone"
    log_event(f"[undo] Reversed {record['type']} for {record['email_id']}")
    return True


@app.post("/api/run")
def run_agent():
    if not RUN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="An agent run is already in progress")
    try:
        # Analyze everything first. A provider or validation failure therefore leaves
        # state unchanged instead of exposing a half-completed run.
        staged = []
        threshold = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.75"))
        for email_id, entry in STATE.items():
            if entry["status"] != "unprocessed":
                continue
            try:
                analysis = analyze_email(entry["email"])
                policy = assess_policy(entry["email"], analysis, threshold)
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Analysis failed for {email_id}: {exc}") from exc
            staged.append((email_id, analysis, policy))

        processed = []
        for email_id, analysis, policy in staged:
            entry = STATE[email_id]
            entry["analysis"] = analysis
            entry["policy"] = policy
            entry["status"] = policy["status"]
            log_event(
                f"[guard] {email_id}: {analysis['category']} confidence={analysis['confidence']:.2f} "
                f"risk={policy['risk_level']} => {policy['status']}"
            )
            if policy["can_auto_execute"]:
                entry["action_id"] = execute_reversible_action(email_id, analysis)
            processed.append(email_id)
    finally:
        RUN_LOCK.release()

    return {"processed": processed, "emails": list(STATE.values())}


@app.get("/api/emails")
def get_emails():
    return list(STATE.values())


@app.post("/api/emails/{email_id}/approve")
def approve_email(email_id: str):
    entry = STATE.get(email_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Unknown email id")
    if entry["status"] not in ("draft_ready", "needs_review"):
        raise HTTPException(status_code=400, detail=f"Nothing pending for status={entry['status']}")

    analysis = entry["analysis"]
    action = analysis.get("proposed_action", {})
    if action.get("type") == "draft_reply":
        log_event(f"[human-approved] Reply approved for {email_id} (delivery simulated)")
    else:
        entry["action_id"] = execute_reversible_action(email_id, analysis, actor="human")

    entry["status"] = "approved"
    return entry


@app.post("/api/emails/{email_id}/reject")
def reject_email(email_id: str):
    entry = STATE.get(email_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Unknown email id")
    if entry["status"] not in ("draft_ready", "needs_review"):
        raise HTTPException(status_code=400, detail=f"Nothing pending for status={entry['status']}")
    entry["status"] = "rejected"
    log_event(f"[human-rejected] Discarded proposed action for {email_id}")
    return entry


@app.get("/api/tasks")
def get_tasks():
    return TASKS


@app.get("/api/events")
def get_events():
    return EVENTS


@app.get("/api/log")
def get_log():
    return LOG


@app.get("/api/actions")
def get_actions():
    return ACTIONS


@app.post("/api/emails/{email_id}/undo")
def undo_email(email_id: str):
    entry = STATE.get(email_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Unknown email id")
    if entry["status"] not in ("auto_executed", "auto_archived", "approved") or not undo_action(entry):
        raise HTTPException(status_code=400, detail=f"No reversible action for status={entry['status']}")
    return entry


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "mode": "demo"
        if os.environ.get("DEMO_MODE", "auto").lower() == "true" or not os.environ.get("ANTHROPIC_API_KEY")
        else "live",
        "emails": len(STATE),
    }


@app.post("/api/reset")
def reset_state():
    for entry in STATE.values():
        entry["analysis"] = None
        entry["policy"] = None
        entry["status"] = "unprocessed"
        entry["action_id"] = None
    TASKS.clear()
    EVENTS.clear()
    LOG.clear()
    ACTIONS.clear()
    return {"ok": True}


frontend_dir = Path(__file__).parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
