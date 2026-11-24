"""Background job: clone a user-supplied GitHub repo and give the agents a goal for it."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from guardian.agents.budget import BudgetLimits
from guardian.agents.models import ModelConfig, ModelDisabledError
from guardian.agents.runner import run_goal
from guardian.remediation.demo import GOAL_ASSESS, GOAL_REMEDIATE, prepare_demo_target
from guardian.scan.baseline import baseline
from guardian.targets import DynamicTargetError, prepare_target

log = logging.getLogger("guardian.jobs")

JOB_GOAL = GOAL_ASSESS
GOALS = {"assess": GOAL_ASSESS, "remediate": GOAL_REMEDIATE}
JOB_LIMITS = {"max_steps": 100, "max_tool_calls": 250, "max_seconds": 900}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:1000]


def run_repo_job(job: dict, repo: str, db: str) -> None:
    """Run one repository end to end. Updates ``job`` in place for the polling endpoint."""
    log.info("job %s start repo=%s branch=%s", job["id"][:8], repo, job.get("branch"))
    try:
        if job.get("demo"):
            job.update(status="cloning", step="Preparing the bundled demo app")
            target = prepare_demo_target()
        else:
            job.update(
                status="cloning", step="Validating the GitHub URL and cloning the repository"
            )
            target = prepare_target(
                repo, progress=lambda msg: job.update(step=msg), branch=job.get("branch")
            )
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
                target["name"], goal=job.get("goal_text") or JOB_GOAL, out_dir=run_id, db=db,
                cfg=ModelConfig(),
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
        log.info("job %s %s: %s", job["id"][:8], job["status"], job["step"])
    except DynamicTargetError as exc:
        log.warning("job %s repository error: %s", job["id"][:8], exc)
        job.update(status="error", step="Repository error", error=_error_text(exc), finished=_now())
    except Exception as exc:
        log.exception("job %s failed", job["id"][:8])
        job.update(status="error", step="Failed", error=_error_text(exc), finished=_now())
