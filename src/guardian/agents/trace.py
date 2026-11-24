"""Turn the recorded agent tool calls into the step list shown by the UI."""

from __future__ import annotations

from typing import Any


def build_steps(calls: list[dict]) -> list[dict]:
    steps: list[dict] = []
    for index, call in enumerate(calls, start=1):
        tool = str(call.get("tool", ""))
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        steps.append(
            {
                "n": index,
                "agent": str(call.get("agent") or "supervisor"),
                "subagent": args.get("subagent_type") if tool == "task" else None,
                "tool": tool,
                "args": args,
                "result_chars": int(call.get("result_chars", 0) or 0),
                "error": bool(call.get("error")),
            }
        )
    return steps


def summarize(trace: dict[str, Any]) -> dict[str, Any]:
    """The Agent Steps view payload from an agent-run.json document."""
    calls = trace.get("tool_calls") if isinstance(trace.get("tool_calls"), list) else []
    hypotheses = trace.get("hypotheses") or []
    return {
        "provider": trace.get("provider"),
        "model": trace.get("model"),
        "generator": "language model" if calls else None,
        "status": trace.get("status"),
        "stop_reason": trace.get("stop_reason"),
        "goal": trace.get("goal"),
        "steps": build_steps(calls),
        "plan": trace.get("plan") or [],
        "hypotheses": hypotheses,
        "usage": trace.get("usage"),
        "final_message": trace.get("final_message"),
        "counts": {
            "tool_calls": len(calls),
            "hypotheses": len(hypotheses),
            "verified": sum(1 for h in hypotheses if h.get("status") == "verified"),
            "blocked": len(trace.get("blocked_tool_calls") or []),
        },
    }
