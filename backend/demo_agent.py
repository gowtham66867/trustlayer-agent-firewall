"""Credential-free deterministic agent used for demos and automated tests."""


def analyze_demo(email: dict[str, str]) -> dict:
    subject = email["subject"].lower()
    body = email["body"].lower()
    text = f"{subject} {body}"

    if "newsletter" in email["from"] or "this week in dev" in text:
        return _analysis(
            "fyi_only", "This is a newsletter with no requested action.", 0.98, False, {"type": "none"}
        )
    if "logo files" in text or "benefits enrollment" in text:
        return _analysis(
            "fyi_only",
            "This is informational and does not require a response.",
            0.91,
            False,
            {"type": "none"},
        )
    if "quick sync" in text or "reschedule" in text:
        return _analysis(
            "needs_scheduling",
            "The sender is proposing a concrete meeting window. A calendar hold is reversible, but the policy engine still checks risk and confidence.",
            0.90,
            False,
            {
                "type": "create_calendar_event",
                "event_title": email["subject"],
                "event_time": "Proposed time from email",
            },
        )
    if "invoice" in text or "expense report" in text:
        return _analysis(
            "actionable_task",
            "The message requests a financial action. It is flagged sensitive so a human must review it.",
            0.94,
            True,
            {
                "type": "create_task",
                "task_title": f"Review: {email['subject']}",
                "task_due": "Before stated deadline",
            },
        )
    if "contract" in text or "liability" in text:
        return _analysis(
            "needs_reply",
            "This is a time-sensitive legal matter. The agent only drafts a cautious acknowledgment for human review.",
            0.96,
            True,
            {
                "type": "draft_reply",
                "reply_text": "Thanks for flagging clause 8.2. I will review it with counsel before taking further action.",
            },
        )
    if "unacceptable" in text or "charged twice" in text:
        return _analysis(
            "needs_reply",
            "The sender is distressed and the issue involves a duplicate charge. A human should review the response.",
            0.97,
            True,
            {
                "type": "draft_reply",
                "reply_text": "I’m sorry about the duplicate charge and delay. I’m escalating this for immediate review.",
            },
        )
    if "github" in email["from"] or "deadline" in text:
        return _analysis(
            "actionable_task",
            "The message contains a clear follow-up item that can be captured as a reversible task.",
            0.88,
            False,
            {"type": "create_task", "task_title": email["subject"], "task_due": "From email"},
        )

    return _analysis(
        "needs_reply",
        "The sender asks for a direct response. A reply is drafted but never sent without approval.",
        0.86,
        False,
        {
            "type": "draft_reply",
            "reply_text": f"Thanks for your message about “{email['subject']}”. I’ll review this and follow up shortly.",
        },
    )


def _analysis(category: str, reasoning: str, confidence: float, sensitive: bool, action: dict) -> dict:
    return {
        "category": category,
        "reasoning": reasoning,
        "confidence": confidence,
        "sensitive": sensitive,
        "proposed_action": action,
    }
