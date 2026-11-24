"""Background job: clone a user-supplied GitHub repo and give the agents a goal for it."""

from __future__ import annotations

from datetime import UTC, datetime

from guardian.agents.budget import BudgetLimits
from guardian.agents.models import ModelConfig, ModelDisabledError
from guardian.agents.runner import run_goal
from guardian.scan.baseline import baseline
from guardian.targets import DynamicTargetError, prepare_target

JOB_GOAL = (
    "Assess the software supply-chain risk of this repository. Find what is in it, what is "
    "vulnerable, and what looks suspicious beyond known CVEs. Report the few things that matter "
    "most, with evidence, what was not checked, and what to do next."
)
JOB_LIMITS = {"max_steps": 100, "max_tool_calls": 250, "max_seconds": 900}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:1000]


def run_repo_job(job: dict, repo: str, db: str) -> None:
    """Run one repository end to end. Updates ``job`` in place for the polling endpoint."""
    try:
        job.update(status="cloning", step="Validating the GitHub URL and cloning the repository")
        target = prepare_target(repo, progress=lambda msg: job.update(step=msg))
        run_id = f"runs/{target['name']}"
        job["run_id"] = run_id

        def on_event(event: dict) -> None:
            args = event.get("args") or {}
            job["steps"] = [
                *job["steps"],
                {
                    "n": len(job["steps"]) + 1,
                    "agent": event["agent"],
                    "subagent": args.get("subagent_type") if event["tool"] == "task" else None,
                    "tool": event["tool"],
                    "args": args,
                    "result_chars": 0,
                    "error": bool(event.get("error")),
                },
            ]
            job["step"] = f"{event['agent']}: {event['tool']}"

        job.update(status="analyzing", step="The agents are planning")
        try:
            doc = run_goal(
                target["name"], goal=JOB_GOAL, out_dir=run_id, db=db, cfg=ModelConfig(),
                limits=BudgetLimits.from_env(**JOB_LIMITS), sandbox="auto", on_event=on_event,
            )  # fmt: skip
        except ModelDisabledError as exc:
            # No model, so no agents. Keep the PDF's scanner-only baseline (tools before LLM).
            job.update(status="scanning", step="No model configured: scanner-only baseline")
            summary = baseline(target["name"], run_id, db=db)
            job.update(
                status="done", step="Scanner-only baseline complete (no agent run)",
                run_id=summary.get("store", {}).get("run_id", run_id),
                findings=summary.get("findings"), error=str(exc), finished=_now(),
            )  # fmt: skip
            return
        explanations = doc.get("explanations") or {}
        job.update(
            status="done" if doc["status"] == "completed" else "error",
            step=f"Agent run {doc['status']}"
            + (f": {doc['stop_reason']}" if doc.get("stop_reason") else ""),
            run_id=doc.get("run_id") or run_id,
            findings=doc.get("findings"),
            accepted=explanations.get("accepted", 0),
            rejected=explanations.get("rejected", 0),
            blocked=len(doc.get("blocked_tool_calls") or []),
            error=None if doc["status"] == "completed" else doc.get("stop_reason"),
            finished=_now(),
        )
    except DynamicTargetError as exc:
        job.update(status="error", step="Repository error", error=_error_text(exc), finished=_now())
    except Exception as exc:
        job.update(status="error", step="Failed", error=_error_text(exc), finished=_now())
