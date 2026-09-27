"""Minimal fail-closed client for gating a Python tool behind TrustLayer."""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.request import Request, urlopen


class ToolNotAuthorized(Exception):
    def __init__(self, decision: dict[str, Any]):
        self.decision = decision
        super().__init__(f"Tool call requires {decision['verdict']}: {decision['explanation']}")


def guarded_call(
    base_url: str,
    proposal: dict[str, Any],
    tool: Callable[..., Any],
    *,
    timeout: float = 5.0,
) -> tuple[Any, dict[str, Any]]:
    """Execute a callable only after ALLOW; REVIEW and BLOCK fail closed."""
    request = Request(
        f"{base_url.rstrip('/')}/api/firewall/evaluate",
        data=json.dumps(proposal).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        decision = json.load(response)
    if decision["verdict"] != "ALLOW":
        raise ToolNotAuthorized(decision)
    return tool(**proposal.get("parameters", {})), decision
