"""Deterministic safety policy for model-proposed inbox actions.

The model may suggest an action, confidence, and sensitivity, but it never gets
the final say on whether code executes.  This module is intentionally free of
LLM calls so its decisions are reproducible and easy to test.
"""

import re
from typing import Any

from pydantic import BaseModel, Field
from typing_extensions import Literal

ActionType = Literal["draft_reply", "create_calendar_event", "create_task", "none"]
Category = Literal["needs_reply", "needs_scheduling", "actionable_task", "fyi_only", "spam"]


class ProposedAction(BaseModel):
    type: ActionType
    reply_text: str = ""
    event_title: str = ""
    event_time: str = ""
    task_title: str = ""
    task_due: str = ""


class Analysis(BaseModel):
    category: Category
    reasoning: str = Field(min_length=3, max_length=2000)
    confidence: float = Field(ge=0, le=1)
    sensitive: bool
    proposed_action: ProposedAction


RISK_PATTERNS = {
    "financial": re.compile(r"\b(invoice|payment|paid|charge[ds]?|refund|expense|bank|\$|usd|inr|₹)\b", re.I),
    "legal": re.compile(r"\b(legal|contract|clause|liability|lawsuit|counsel|countersign)\b", re.I),
    "distressed_sender": re.compile(
        r"\b(unacceptable|angry|furious|disput(?:e|ing)|complaint|escalat(?:e|ion))\b", re.I
    ),
}

INJECTION_PATTERNS = [
    re.compile(r"ignore (?:all |the )?(?:previous|prior|system) instructions", re.I),
    re.compile(r"(?:system|developer) (?:message|prompt|instruction)", re.I),
    re.compile(r"(?:mark|set|return).{0,30}(?:confidence|sensitive).{0,20}(?:1(?:\.0)?|false)", re.I),
    re.compile(r"(?:call|use|invoke) (?:the )?(?:tool|function)", re.I),
]

CATEGORY_ACTIONS = {
    "needs_reply": {"draft_reply"},
    "needs_scheduling": {"create_calendar_event", "draft_reply"},
    "actionable_task": {"create_task", "draft_reply"},
    "fyi_only": {"none"},
    "spam": {"none"},
}


def validate_analysis(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized analysis or raise a Pydantic validation error."""
    return Analysis.model_validate(raw).model_dump()


def assess_policy(email: dict[str, str], analysis: dict[str, Any], threshold: float) -> dict[str, Any]:
    """Independently decide whether the proposed action can execute."""
    text = " ".join((email.get("from", ""), email.get("subject", ""), email.get("body", "")))
    action_type = analysis["proposed_action"]["type"]
    signals: list[str] = []
    checks: list[dict[str, Any]] = []

    for name, pattern in RISK_PATTERNS.items():
        if pattern.search(text):
            signals.append(name)

    injection_detected = any(pattern.search(text) for pattern in INJECTION_PATTERNS)
    if injection_detected:
        signals.append("prompt_injection")

    action_aligned = action_type in CATEGORY_ACTIONS[analysis["category"]]
    if not action_aligned:
        signals.append("category_action_mismatch")

    irreversible = action_type == "draft_reply"
    model_sensitive = bool(analysis["sensitive"])
    deterministic_sensitive = bool(signals)
    high_confidence = analysis["confidence"] >= threshold

    checks.extend(
        [
            {"name": "schema_valid", "passed": True, "detail": "Model output matches the enforced schema."},
            {
                "name": "confidence_threshold",
                "passed": high_confidence,
                "detail": f"{analysis['confidence']:.2f} >= {threshold:.2f}",
            },
            {
                "name": "content_risk_scan",
                "passed": not deterministic_sensitive,
                "detail": ", ".join(signals) or "No deterministic risk signals.",
            },
            {
                "name": "category_action_alignment",
                "passed": action_aligned,
                "detail": f"{analysis['category']} -> {action_type}",
            },
            {
                "name": "reversibility",
                "passed": not irreversible,
                "detail": "Draft replies always require a human."
                if irreversible
                else "Action is locally reversible.",
            },
        ]
    )

    safe_to_auto_execute = (
        high_confidence
        and not model_sensitive
        and not deterministic_sensitive
        and action_aligned
        and not irreversible
    )

    if irreversible:
        status = "needs_review" if (model_sensitive or deterministic_sensitive) else "draft_ready"
    elif safe_to_auto_execute:
        status = "auto_archived" if action_type == "none" else "auto_executed"
    else:
        status = "needs_review"

    risk_level = (
        "high" if injection_detected or irreversible or model_sensitive else ("medium" if signals else "low")
    )
    rationale = (
        "Auto-execution allowed: every deterministic guard passed."
        if safe_to_auto_execute
        else "Human review required: "
        + "; ".join(
            signals or (["irreversible action"] if irreversible else ["confidence or model sensitivity gate"])
        )
    )
    return {
        "status": status,
        "can_auto_execute": safe_to_auto_execute,
        "risk_level": risk_level,
        "risk_signals": signals,
        "checks": checks,
        "rationale": rationale,
    }
