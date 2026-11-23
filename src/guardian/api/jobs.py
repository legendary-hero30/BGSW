"""Background job: clone a user-supplied GitHub repo, scan it and explain it with DeepInfra."""

from __future__ import annotations

from datetime import UTC, datetime

from guardian.agents.models import ModelConfig, ModelDisabledError
from guardian.agents.orchestrator import run_agents
from guardian.agents.report import export
from guardian.agents.tools import AgentContext
from guardian.agents.trace import build_steps
from guardian.scan.baseline import baseline
from guardian.targets import DynamicTargetError, prepare_target

MAX_FINDINGS = 10


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
        job.update(
            status="scanning",
            step="Discovery, scanners, anomaly rules and risk scoring",
            run_id=run_id,
        )
        summary = baseline(target["name"], run_id, db=db)
        job["run_id"] = summary.get("store", {}).get("run_id", run_id)
        job["findings"] = summary.get("findings")
        if not summary.get("findings"):
            job.update(
                status="done",
                step="Scan complete: no findings to explain",
                finished=_now(),
            )
            return

        job.update(status="analyzing", step="Generating gated explanations with DeepInfra")
        cfg = ModelConfig()  # DeepInfra and its default tool-calling model
        ctx = AgentContext(
            target=target["name"],
            out_dir=job["run_id"],
            db=db,
            provider=cfg.provider,
            model=cfg.model,
            run_id=job["run_id"],
            max_findings=MAX_FINDINGS,
        )
        ctx.on_step = lambda _entry: job.update(steps=build_steps(ctx.log))
        try:
            outcome = run_agents(ctx, cfg, "analyze")
        except ModelDisabledError as exc:
            job.update(
                status="done",
                step="Scan complete; DeepInfra analysis is not configured",
                error=str(exc),
                steps=build_steps(ctx.log),
                finished=_now(),
            )
            return
        doc = export(ctx, cfg, outcome)
        job.update(
            status="done",
            step="Complete",
            accepted=len(doc["accepted"]),
            rejected=len(doc["rejected"]),
            blocked=len(doc["blocked_tool_calls"]),
            steps=build_steps(ctx.log),
            finished=_now(),
        )
    except DynamicTargetError as exc:
        job.update(status="error", step="Repository error", error=_error_text(exc), finished=_now())
    except Exception as exc:
        job.update(status="error", step="Failed", error=_error_text(exc), finished=_now())
