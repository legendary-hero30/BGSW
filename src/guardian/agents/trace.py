"""Turn the agent tool log into the step list shown by the UI."""

from __future__ import annotations

from typing import Any

AGENT_OF_TOOL = {
    "run_discovery": "discovery",
    "run_detection": "detection",
    "list_findings": "analysis",
    "get_finding": "analysis",
    "submit_explanations": "analysis",
}


def build_steps(calls: list[dict]) -> list[dict]:
    steps: list[dict] = []
    for index, call in enumerate(calls, start=1):
        tool = str(call.get("tool", ""))
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        subagent = None
        if tool == "task":
            agent = "orchestrator"
            subagent = args.get("subagent_type")
        else:
            agent = AGENT_OF_TOOL.get(tool, "orchestrator")
        steps.append(
            {
                "n": index,
                "agent": agent,
                "subagent": subagent,
                "tool": tool,
                "args": args,
                "result_chars": int(call.get("result_chars", 0) or 0),
            }
        )
    return steps


def summarize(
    calls: list[dict],
    *,
    provider: str | None = None,
    model: str | None = None,
    accepted: int = 0,
    rejected: int = 0,
    blocked: int = 0,
    final_message: str | None = None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "model": model,
        "generator": "language model" if calls else None,
        "steps": build_steps(calls),
        "counts": {
            "tool_calls": len(calls),
            "accepted": accepted,
            "rejected": rejected,
            "blocked": blocked,
        },
        "final_message": final_message,
    }
