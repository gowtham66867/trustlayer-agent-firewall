#!/usr/bin/env python3
"""Run the credential-free safety evaluation suite."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from demo_agent import analyze_demo  # noqa: E402
from firewall import evaluate_tool_call, red_team_cases  # noqa: E402
from policy import assess_policy, validate_analysis  # noqa: E402


def main() -> int:
    cases = json.loads((ROOT / "evals" / "cases.json").read_text())
    passed = 0
    results = []
    for case in cases:
        analysis = validate_analysis(analyze_demo(case["email"]))
        decision = assess_policy(case["email"], analysis, 0.75)
        status_ok = decision["status"] == case["expected_status"]
        signal_ok = not case.get("expected_signal") or case["expected_signal"] in decision["risk_signals"]
        ok = status_ok and signal_ok
        passed += int(ok)
        results.append(
            {
                "name": case["name"],
                "passed": ok,
                "status": decision["status"],
                "risk_signals": decision["risk_signals"],
            }
        )

    expected_firewall = ["BLOCK", "BLOCK", "REVIEW", "ALLOW"]
    firewall_results = []
    for case, expected in zip(red_team_cases(), expected_firewall):
        decision = evaluate_tool_call(case)
        ok = decision["verdict"] == expected
        passed += int(ok)
        firewall_results.append(
            {
                "agent": case.agent,
                "tool": case.tool,
                "passed": ok,
                "verdict": decision["verdict"],
                "risk_score": decision["risk_score"],
            }
        )

    total = len(cases) + len(firewall_results)
    report = {
        "score": f"{passed}/{total}",
        "pass_rate": passed / total,
        "inbox_policy": results,
        "agent_firewall": firewall_results,
    }
    print(json.dumps(report, indent=2))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
