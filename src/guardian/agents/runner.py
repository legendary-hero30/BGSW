"""Run one goal end to end: set up the session, let the supervisor work, record the outcome.

The runner owns lifecycle only. It never chooses what the agents do. It stops when the
supervisor finishes, the budget is spent, or an error occurs, and in every case exports what
exists (a clearly labelled partial report if the agents did not produce one).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from guardian.agents.budget import BudgetExhausted, BudgetLimits, BudgetTracker
from guardian.agents.ledger import Ledger
from guardian.agents.models import ModelConfig, build_model
from guardian.agents.report import export_run
from guardian.agents.session import Session
from guardian.agents.supervisor import build_supervisor, prompt_versions
from guardian.redact import redact
from guardian.sandbox import backend_report, select_sandbox
from guardian.scan.pipeline import Pipeline
from guardian.store import DEFAULT_DB

RECURSION_LIMIT = 300  # LangGraph supersteps; the budget is the real bound
DEFAULT_GOAL = (
    "Assess the software supply-chain risk of the target application and produce an "
    "evidence-backed report of what matters most, what was and was not checked, and what "
    "to do next."
)


def default_out_dir(target: str) -> str:
    return f"runs/agent-{target}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


def run_goal(
    target: str,
    *,
    goal: str = DEFAULT_GOAL,
    out_dir: str | None = None,
    db: str | Path = DEFAULT_DB,
    cfg: ModelConfig | None = None,
    limits: BudgetLimits | None = None,
    sandbox: str = "auto",
    on_event: Callable[[dict], None] | None = None,
) -> dict:
    """Run the supervisor on a goal. Returns the outcome record (also written to the run dir)."""
    os.environ.setdefault("LANGSMITH_TRACING", "false")  # no tracing upload unless opted in
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
    cfg = cfg or ModelConfig()
    limits = limits or BudgetLimits.from_env()
    limits.validate()
    model = build_model(cfg)  # raises ModelDisabledError before anything is created

    out = out_dir or default_out_dir(target)
    pipeline = Pipeline(target, out, db)
    backend, reason = select_sandbox(sandbox)
    ledger = Ledger(db)
    ledger.reap_stale()
    S = Session(  # noqa: N806
        goal=redact(goal),
        target=target,
        out_dir=out,
        db=str(db),
        provider=cfg.provider,
        model=cfg.model,
        ledger=ledger,
        budget=BudgetTracker(limits),
        pipeline=pipeline,
        sandbox=backend,
        sandbox_reason=reason,
        on_event=on_event,
    )
    ledger.start_run(
        goal=S.goal,
        target=target,
        provider=cfg.provider,
        model=cfg.model,
        budget=S.budget.snapshot()["limits"],
        prompts=prompt_versions(),
    )
    ledger.set_stored_run(pipeline.run_id)  # lets the UI follow a run before findings exist
    ledger.log(
        "runner",
        "sandbox",
        backend.name if backend else "none",
        {"reason": reason, "backends": backend_report()},
    )
    blocked: list[str] = []
    status, stop_reason, final = "completed", None, None
    try:
        agent = build_supervisor(model, S, blocked)
        task = (
            f"GOAL: {S.goal}\nTARGET: {target} (the only repository you can analyze)\n"
            f"BUDGET: {S.budget.describe()}\n"
            f"SANDBOX: {reason}\n"
            "Plan, delegate to your specialists, adapt to what they find, and finish with an "
            "accepted report."
        )
        result = agent.invoke(
            {"messages": [{"role": "user", "content": task}]},
            config={"recursion_limit": RECURSION_LIMIT},
        )
        content = result["messages"][-1].content
        final = content if isinstance(content, str) else str(content)
        if S.report_markdown is None:
            status = "incomplete"
            stop_reason = "the supervisor finished without an accepted report"
    except BudgetExhausted as exc:
        status, stop_reason = "budget_exhausted", exc.reason
    except Exception as exc:
        status, stop_reason = "error", redact(f"{type(exc).__name__}: {exc}")[:500]
        ledger.log("runner", "run_error", type(exc).__name__, {"message": stop_reason})
    outcome = {
        "status": status,
        "stop_reason": stop_reason,
        "final": final,
        "blocked_tool_calls": blocked,
    }
    try:
        doc = export_run(S, outcome)
    finally:
        ledger.finish_run(status, stop_reason, S.budget.snapshot(), S.report_markdown)
        ledger.close()
    doc["agent_run_id"] = S.ledger.agent_run_id
    return doc
