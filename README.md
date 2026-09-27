# TrustLayer Agent Firewall

[![Quality](https://github.com/gowtham66867/trustlayer-agent-firewall/actions/workflows/quality.yml/badge.svg)](https://github.com/gowtham66867/trustlayer-agent-firewall/actions/workflows/quality.yml)

> Runtime authorization, adversarial protection, and tamper-evident auditing for autonomous AI agents.

TrustLayer sits between AI agents and the tools they want to call. Every proposed side effect receives an `ALLOW`, `REVIEW`, or `BLOCK` verdict before execution. The inbox agent is a concrete adapter demonstrating guarded autonomy for replies, tasks, calendar events, and archiving. A Python SDK shows how to gate an actual callable on an `ALLOW` decision.

Built for Agenthon 2026. Runs end-to-end without credentials.

**Live demo:** [trustlayer-agent-firewall.onrender.com](https://trustlayer-agent-firewall.onrender.com) — hosted on Render's free plan in deterministic demo mode. The instance may take about a minute to wake after inactivity; its local demo data is shared and may reset on restart. Do not enter real secrets or personal data.

## Why it matters

Most inbox agents either stop at summarization or auto-act based on the model's own confidence. That creates a circular trust problem: the system being evaluated also decides whether it is safe.

TrustLayer separates the responsibilities:

```text
Untrusted email
      ↓
LLM or deterministic demo classifier
      ↓ structured proposal
Pydantic schema validation
      ↓
Deterministic safety gate
  ├─ content risk scan
  ├─ prompt-injection detection
  ├─ category/action alignment
  ├─ confidence threshold
  └─ reversibility check
      ↓
Auto-execute reversible action OR request human approval
      ↓
Audit log + one-click undo
```

The model can propose an action. It cannot grant itself permission to execute it.

## The prize demo: Agent Firewall Attack Lab

Click **Red-Team Demo** to run four predefined adversarial proposals through the firewall:

- A prompt-injected inbox agent attempts to exfiltrate a payroll file.
- A finance agent attempts an irreversible $48,000 transfer.
- A support agent attempts to promise a refund to an angry customer.
- A project agent proposes a safe, reversible task.

The firewall blocks two calls, routes one for human review, safely allows one, and writes every decision to a SQLite-backed SHA-256 hash chain. The interface displays risk scores, triggered policy rules, the review queue, and chain verification live. Authorized tools create local persisted artifacts; nothing is sent to an external account.

The **Live Playground** is the unscripted proof: edit the agent, source, tool, destination, content, parameters, confidence, and data class, then submit a fresh request. The API produces a new decision ID and rule trace. A safe task can create an undoable local artifact; an injected secret share or money transfer is blocked. This is a deterministic local security prototype, not a claim that all prompt injections are detected.

## Judge demo — 60 seconds

```bash
git clone https://github.com/gowtham66867/trustlayer-agent-firewall.git
cd trustlayer-agent-firewall
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn main:app --app-dir backend --port 8000
```

Open [the live demo](https://trustlayer-agent-firewall.onrender.com) or [http://localhost:8000](http://localhost:8000). Click **Red-Team Demo** for the headline demonstration or **Run Agent** for the inbox workflow.

No API key is required. The application automatically selects its deterministic demo agent while exercising the real schema, policy, execution, approval, audit, and undo pipeline.

Suggested walkthrough:

1. Open the newsletter: every safety check passes and it is archived automatically.
2. Open the overdue invoice: the model is confident, but the deterministic financial-risk check blocks execution.
3. Open the angry customer's email: financial and distressed-sender signals force review.
4. Open an auto-created task or event and click **Undo action**.
5. Open **Live Playground**, choose **Safe task**, and evaluate it. Open **Review Queue** and create its local task artifact; use **Undo** to reverse it.
6. Return to **Live Playground**, choose **Injection attack**, and evaluate again. Its `BLOCK` decision has no execution control.
7. Open **Audit Proof**: inspect the persistent event chain and its verification status.

## Live model mode

```bash
cp backend/.env.example backend/.env
```

Set a model available to your Anthropic account:

```env
DEMO_MODE=false
ANTHROPIC_API_KEY=...
CLAUDE_MODEL=...
CONFIDENCE_THRESHOLD=0.75
```

`DEMO_MODE=auto` is the default: live mode is used when a key exists; otherwise the deterministic demo runs.

## Trust policy

| Action | Automatic? | Rule |
|---|---:|---|
| Draft reply | Never | Sending is irreversible; a human must approve |
| Create task | Conditional | High confidence, aligned category, and no risk signals |
| Create calendar hold | Conditional | Same deterministic gates; action remains undoable |
| Archive | Conditional | Only high-confidence FYI/spam with no risk signals |
| Financial, legal, distressed, injected | Never | Deterministic rules override model confidence |

Every decision displays its five checks, risk level, rationale, model reasoning, and confidence.

## Reliability and evaluation

```bash
pip install -r requirements-dev.txt
ruff check backend tests scripts sdk
ruff format --check backend tests scripts sdk
pytest --cov=backend --cov-report=term-missing
python scripts/evaluate.py
python scripts/smoke_live.py          # with the server running
```

Verified locally:

- 50 automated tests passing
- 10/10 combined inbox-policy and agent-firewall evaluations passing
- Credential-free end-to-end API test
- Atomic failure test proving partial runs do not commit
- Prompt-injection, financial, legal, emotional-risk, schema, transition, and undo tests
- Ruff lint and formatting checks
- GitHub Actions quality workflow

The 50-test suite includes a 20-case firewall regression matrix, SQLite reopen/persistence, secret-field redaction, expiry, replay prevention, reviewer-token enforcement, blocked-call execution denial, local artifact and undo transitions, public-response privacy, SDK fail-closed behavior, and audit-tamper detection. The regression matrix is a hand-authored local fixture, not an independent benchmark. Coverage percentages are intentionally omitted until recalculated for this version.

`scripts/smoke_live.py` runs six end-to-end checks against a running local or deployed URL, including authorized local artifact creation, undo, blocked injection, denied execution, and audit verification. Pass a public base URL as its argument after deployment.

Adversarial cases live in `evals/cases.json`. The harness emits machine-readable JSON and exits non-zero on regression.

## Gate a real Python tool

```python
from sdk.trustlayer import guarded_call

result, decision = guarded_call(
    "http://localhost:8000",
    {
        "agent": "project-agent",
        "source": "team-email",
        "content": "Please create a sprint task",
        "tool": "create_task",
        "parameters": {"title": "Plan sprint"},
        "confidence": 0.95,
        "reversible": True,
        "idempotency_key": "sprint-task-2026-09-27",
    },
    create_task,
)
```

`guarded_call` raises `ToolNotAuthorized` for `REVIEW` or `BLOCK`, and fails closed if the service is unavailable. The application must provide `create_task` and handle reviewer-approved execution separately. Set `TRUSTLAYER_POLICY=startup|enterprise|regulated` before server startup to select a preset; set `TRUSTLAYER_REVIEW_TOKEN` to require an `X-Review-Token` header for approvals/rejections.

## Reliability properties

- **Schema constrained:** malformed model output is rejected before policy evaluation.
- **Independent authorization:** deterministic code—not the LLM—decides whether execution is permitted.
- **Atomic batch runs:** all emails are analyzed before state is committed.
- **Concurrency guarded:** overlapping runs receive `409 Conflict` rather than duplicating actions.
- **Idempotent workflow:** only unprocessed emails enter a run.
- **Valid state transitions:** approval and rejection only apply to pending items.
- **Recoverable actions:** task, event, and archive actions receive IDs and can be undone.
- **Auditable:** every guard and execution decision is visible in the UI and log.
- **Safe demo:** judges can verify the architecture without credentials or real accounts.
- **Policy as code:** `startup`, `enterprise`, and `regulated` JSON presets define tool permissions, trusted destinations, confidence thresholds, and protected data classes.
- **Persistent authorization:** decisions and audit entries survive local process restarts in SQLite. Idempotency keys reject replayed calls; review authorizations expire.
- **Fail-closed SDK:** `sdk/trustlayer.py` calls a Python tool only after an `ALLOW` response; `REVIEW`, `BLOCK`, and service failures do not execute it.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Mode and service health |
| `POST` | `/api/run` | Atomically analyze all unprocessed emails |
| `GET` | `/api/emails` | Analyses, policy decisions, and states |
| `POST` | `/api/emails/{id}/approve` | Approve a pending proposal |
| `POST` | `/api/emails/{id}/reject` | Reject a pending proposal |
| `POST` | `/api/emails/{id}/undo` | Reverse an executed local action |
| `GET` | `/api/tasks` | Created task artifacts |
| `GET` | `/api/events` | Created calendar artifacts |
| `GET` | `/api/actions` | Action ledger including undo state |
| `POST` | `/api/firewall/evaluate` | Authorize any proposed agent tool call |
| `GET` | `/api/policy` | Inspect the active policy preset |
| `GET` | `/api/firewall/decisions` | Inspect persistent decisions and states |
| `GET` | `/api/firewall/review` | Pending review queue |
| `GET` | `/api/firewall/artifacts` | Persisted local tool artifacts and undo states |
| `POST` | `/api/firewall/decisions/{id}/approve` | Human approval (optional reviewer token) |
| `POST` | `/api/firewall/decisions/{id}/reject` | Reject a proposal |
| `POST` | `/api/firewall/decisions/{id}/execute` | Simulate an authorized tool execution |
| `POST` | `/api/firewall/decisions/{id}/undo` | Undo eligible local artifacts |
| `POST` | `/api/red-team` | Run the live adversarial attack suite |
| `GET` | `/api/firewall/metrics` | Allow, review, and block telemetry |
| `GET` | `/api/audit` | Hash-linked audit entries and chain verification |
| `GET` | `/api/log` | Human-readable transparency log |
| `POST` | `/api/reset` | Reset the deterministic demo |

## Project layout

```text
backend/
  agent.py          Anthropic tool-use adapter
  firewall.py       generic ALLOW / REVIEW / BLOCK runtime firewall
  audit.py          SHA-256 hash-chained decision ledger
  store.py          SQLite decision state, expiry, replay protection
  demo_agent.py     deterministic credential-free agent
  policy.py         schema and independent safety gate
  main.py           API, state machine, atomic execution, undo
  data.py           12 representative inbox scenarios
frontend/
  index.html        accessible application shell
  app.js            rendering and API interactions
  style.css         responsive dashboard and policy trace UI
evals/cases.json    adversarial evaluation dataset
evals/firewall_matrix.json  20-case firewall regression matrix
policies/           startup, enterprise, and regulated policy presets
sdk/trustlayer.py   fail-closed Python tool wrapper
scripts/evaluate.py evaluation harness
scripts/smoke_live.py live API smoke test
tests/              policy and API reliability tests
Dockerfile          production-style container
```

## Deployment

```bash
docker build -t inbox-zero-agent .
docker run --rm -p 8000:8000 -e DEMO_MODE=true inbox-zero-agent
```

The public demo runs this container on Render's $0/month plan with `DEMO_MODE=true`. For another host, deploy the same container with no secrets for demo mode. The free Render instance spins down after inactivity and has no persistent disk.

## Honest limitations

This submission deliberately avoids external side effects. Authorized task, calendar, and archive calls create persistent local artifacts; authorized email/message calls create local drafts rather than sending. Unsupported tools have no execution adapter even after approval. This makes the safety model testable without risking a judge's inbox or calendar. The SDK can gate a caller-provided function, but is not a replacement for authentication and authorization at the tool provider.

Firewall decisions and audit events persist in local SQLite (`TRUSTLAYER_DB` overrides the path). The inbox demo's email/task/event state remains in memory. On hosts with ephemeral filesystems, mount a persistent volume or use a durable database before claiming restart persistence. The hash chain detects accidental or partial row tampering, but a database administrator could rewrite the entire chain; independent external anchoring is required for stronger proof. Secret redaction is best-effort, not a guarantee for arbitrary sensitive content. The optional `TRUSTLAYER_REVIEW_TOKEN` protects approve/reject endpoints in a controlled deployment; set it and add proper identity, TLS, and role-based access before exposing the API publicly.

## Security principles

- Email content is untrusted data, never authority.
- Model reasoning is evidence for a proposal, never authorization.
- Irreversible communication requires explicit human approval.
- Sensitive content always fails closed.
- Reversible automation must remain observable and undoable.

## License

MIT
