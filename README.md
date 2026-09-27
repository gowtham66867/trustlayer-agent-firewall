# TrustLayer Agent Firewall

[![Quality](https://github.com/gowtham66867/agenthon-inbox-agent/actions/workflows/quality.yml/badge.svg)](https://github.com/gowtham66867/agenthon-inbox-agent/actions/workflows/quality.yml)

> Runtime authorization, adversarial protection, and tamper-evident auditing for autonomous AI agents.

TrustLayer sits between AI agents and the tools they want to call. Every proposed side effect receives an `ALLOW`, `REVIEW`, or `BLOCK` verdict before execution. The inbox agent is a concrete adapter demonstrating guarded autonomy for replies, tasks, calendar events, and archiving.

Built for Agenthon 2026. Runs end-to-end without credentials.

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

Click **Red-Team Demo** to run four adversarial tool calls through the firewall:

- A prompt-injected inbox agent attempts to exfiltrate a payroll file.
- A finance agent attempts an irreversible $48,000 transfer.
- A support agent attempts to promise a refund to an angry customer.
- A project agent proposes a safe, reversible task.

The firewall blocks two calls, routes one for human review, safely allows one, and writes every decision to a SHA-256 hash-chained audit ledger. The interface displays risk scores, triggered policy rules, and cryptographic chain verification live.

## Judge demo — 60 seconds

```bash
git clone https://github.com/gowtham66867/agenthon-inbox-agent.git
cd agenthon-inbox-agent
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn main:app --app-dir backend --port 8000
```

Open [http://localhost:8000](http://localhost:8000). Click **Red-Team Demo** for the headline demonstration or **Run Agent** for the inbox workflow.

No API key is required. The application automatically selects its deterministic demo agent while exercising the real schema, policy, execution, approval, audit, and undo pipeline.

Suggested walkthrough:

1. Open the newsletter: every safety check passes and it is archived automatically.
2. Open the overdue invoice: the model is confident, but the deterministic financial-risk check blocks execution.
3. Open the angry customer's email: financial and distressed-sender signals force review.
4. Open an auto-created task or event and click **Undo action**.
5. Show the transparency log and run the adversarial evaluation suite.

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
ruff check backend tests scripts
ruff format --check backend tests scripts
pytest --cov=backend --cov-report=term-missing
python scripts/evaluate.py
```

Verified baseline:

- 19 automated tests passing
- 91% measured backend coverage
- 100% coverage of the deterministic policy engine
- 10/10 combined inbox-policy and agent-firewall evaluations passing
- Credential-free end-to-end API test
- Atomic failure test proving partial runs do not commit
- Prompt-injection, financial, legal, emotional-risk, schema, transition, and undo tests
- Ruff lint and formatting checks
- GitHub Actions quality workflow

Adversarial cases live in `evals/cases.json`. The harness emits machine-readable JSON and exits non-zero on regression.

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
  demo_agent.py     deterministic credential-free agent
  policy.py         schema and independent safety gate
  main.py           API, state machine, atomic execution, undo
  data.py           12 representative inbox scenarios
frontend/
  index.html        accessible application shell
  app.js            rendering and API interactions
  style.css         responsive dashboard and policy trace UI
evals/cases.json    adversarial evaluation dataset
scripts/evaluate.py evaluation harness
tests/              policy and API reliability tests
Dockerfile          production-style container
```

## Deployment

```bash
docker build -t inbox-zero-agent .
docker run --rm -p 8000:8000 -e DEMO_MODE=true inbox-zero-agent
```

Deploy the container to Render, Railway, Fly.io, or another compatible host. Demo mode needs no secrets.

## Honest limitations

This submission deliberately simulates external side effects. Tasks and events are local artifacts, and an approved reply is recorded rather than delivered. This makes the safety model fully testable without risking a judge's inbox or calendar. Production adapters would use OAuth, persistent storage, encrypted credentials, provider idempotency keys, and the same policy interface.

State is in memory and resets when the server restarts. This is appropriate for the deterministic submission demo, not a claim of production persistence.

## Security principles

- Email content is untrusted data, never authority.
- Model reasoning is evidence for a proposal, never authorization.
- Irreversible communication requires explicit human approval.
- Sensitive content always fails closed.
- Reversible automation must remain observable and undoable.

## License

MIT
