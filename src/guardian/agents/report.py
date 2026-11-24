"""The Guardian report: gate, deterministic facts appendix, fallback, and run exports.

The supervisor writes the analysis. Code writes the facts: the appendix states coverage, budget
use, verified/unverified hypotheses and security flags from stored records, so a model cannot
omit a coverage gap or overstate a result. If no agent report is accepted (budget spent, error),
a clearly labelled partial report is generated from the store instead, with no model text.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from guardian.agents.gate import facts_for, grounding_problems
from guardian.store import accepted_explanations, connect

if TYPE_CHECKING:
    from guardian.agents.session import Session

MIN_CHARS, MAX_CHARS = 200, 15_000
FINDING_REF = re.compile(r"\bF-\d{3,}\b")
HYPOTHESIS_REF = re.compile(r"\bH-\d{2,}\b")


class ReportRejectedError(ValueError):
    pass


def check_report(S: Session, markdown: str) -> list[str]:  # noqa: N803
    if not MIN_CHARS <= len(markdown) <= MAX_CHARS:
        return [f"the report must be {MIN_CHARS} to {MAX_CHARS} characters (got {len(markdown)})"]
    fs = S.finding_set()
    graph_labels = [S.graph().label(n.bom_ref) for n in S.graph().nodes]
    facts = facts_for(
        fs.findings, scope="the run", extra_labels=graph_labels, evidence=S.evidence()
    )
    problems = grounding_problems(markdown, facts)
    known = {f.id for f in fs.findings}
    for fid in sorted(set(FINDING_REF.findall(markdown)) - known):
        problems.append(f"mentions finding {fid}, which does not exist in this run")
    hypotheses = {h["id"]: h for h in S.ledger.hypotheses()}
    for hid in sorted(set(HYPOTHESIS_REF.findall(markdown))):
        status = hypotheses.get(hid, {}).get("status")
        if status != "verified":
            problems.append(
                f"mentions hypothesis {hid} which is {status or 'unknown'}: only verified "
                "hypotheses may be asserted"
            )
    waiting = [h["id"] for h in hypotheses.values() if h["status"] == "proposed"]
    if waiting:
        problems.append(
            f"hypotheses {waiting} have not been reviewed: have the verifier agent rule on "
            "them (verified, rejected or needs_more_evidence) before submitting"
        )
    return problems


def submit_report(S: Session, markdown: str) -> dict:  # noqa: N803
    problems = check_report(S, markdown)
    if problems:
        S.ledger.log("supervisor", "gate_rejection", "report", {"problems": problems})
        return {"accepted": False, "problems": problems}
    S.report_markdown = f"{markdown.rstrip()}\n\n{facts_appendix(S)}"
    S.ledger.save_report(S.report_markdown)
    S.ledger.log("supervisor", "report", "accepted", {"chars": len(S.report_markdown)})
    return {"accepted": True, "chars": len(S.report_markdown)}


def facts_appendix(S: Session) -> str:  # noqa: N803
    """Deterministic facts about the run, written by code from stored records."""
    info = S.ledger.run_info()
    lines = ["---", "## Run facts (deterministic, written by code, not by the model)", ""]
    lines += [f"- Goal: {info['goal']}", f"- Target: {S.target}; stored run `{S.run_id}`"]
    lines += [f"- Model: {S.provider}:{S.model}", f"- Sandbox: {S.sandbox_reason}"]
    usage = S.budget.snapshot()
    lines.append(f"- Budget used: {S.budget.describe()}")
    if usage["unknown_usage_calls"]:
        lines.append(f"- {usage['unknown_usage_calls']} model calls reported no token usage")
    if S.findings_built:
        s = json.loads((S.pipeline.out / "baseline.json").read_text())
        cov = s["coverage"]
        lines += [
            f"- Findings: {s['findings']} (by risk level {s['by_risk_level']})",
            f"- Scanners run: {cov['scanners_run'] or 'none'}; NOT run: "
            f"{cov['scanners_not_run'] or 'none'}",
            f"- Dockerfile scanned: {cov['dockerfile_scanned']}; workflows scanned: "
            f"{cov['workflows_scanned']}; base image scanned: {cov['image_scanned']}; "
            f"anomaly rules run: {cov['anomaly_rules_run']}",
        ]
        conn = connect(S.db)
        try:
            accepted = accepted_explanations(conn, S.run_id)
        finally:
            conn.close()
        rejections = S.ledger.count_events("gate_rejection")
        lines.append(
            f"- Findings were built {S.builds} time(s); explanations accepted by the gate "
            f"(current build): {len(accepted)}; gate rejections logged this run: {rejections}"
        )
    else:
        lines.append("- No findings were built in this run.")
    hyps = S.ledger.hypotheses()
    if hyps:
        lines += ["", "| Hypothesis | Status | Confidence | Claim |", "|---|---|---|---|"]
        lines += [
            f"| {h['id']} | {h['status']} | {h['confidence']} | {h['claim'][:160]} |" for h in hyps
        ]
    if S.injection_flags:
        lines += [
            "",
            f"- Prompt-injection-like text flagged in repository files: {len(S.injection_flags)}",
        ]
        lines += [f"  - {f['file']}:{f['line']} ({f['pattern']})" for f in S.injection_flags[:10]]
    return "\n".join(lines) + "\n"


def partial_report(S: Session, stop_reason: str) -> str:  # noqa: N803
    """Built from stored facts only, when no agent report was accepted."""
    lines = [
        "# Guardian report (PARTIAL: no model-written analysis was accepted)",
        "",
        f"The run stopped: {stop_reason}. Below is only what the deterministic tools recorded.",
        "",
        "## Plan at stop",
    ]
    plan = S.ledger.plan()
    lines += [f"- {p['id']} [{p['status']}] {p['goal']}" for p in plan] or [
        "- no plan was recorded"
    ]
    if S.findings_built:
        fs = S.finding_set()
        lines += [
            "",
            "## Top findings by risk",
            "",
            "| ID | Risk | Type | Package |",
            "|---|---|---|---|",
        ]
        for f in fs.findings[:10]:
            risk = f"{f.risk.score} {f.risk.level.value}" if f.risk else "unscored"
            lines.append(
                f"| {f.id} | {risk} | {f.type.value} | {f.component.name}@{f.component.version} |"
            )
    lines += ["", facts_appendix(S)]
    return "\n".join(lines)


def export_run(S: Session, outcome: dict) -> dict:  # noqa: N803
    """Write agent-report.md, agent-run.json, agent-trace.json and explanations.* to the run dir."""
    out = S.pipeline.out
    report = S.report_markdown
    if report is None:
        report = partial_report(S, outcome.get("stop_reason") or "no report submitted")
    (out / "agent-report.md").write_text(report)
    events = S.ledger.events()
    calls = [
        {
            "n": e["seq"],
            "agent": e["agent"],
            "tool": e["name"],
            "args": e["payload"].get("args", {}),
            "result_chars": e["payload"].get("result_chars", 0),
            "ms": e["payload"].get("ms"),
            "error": e["payload"].get("error", False),
        }
        for e in events
        if e["kind"] in {"tool_call", "delegate"}
    ]
    for c in calls:
        c["subagent"] = c["args"].get("subagent_type") if c["tool"] == "task" else None
    doc = {
        "agent_run_id": S.ledger.agent_run_id,
        "out_dir": S.run_id,
        "run_id": S.run_id if S.findings_built else None,
        "status": outcome["status"],
        "stop_reason": outcome.get("stop_reason"),
        "provider": S.provider,
        "model": S.model,
        "goal": S.goal,
        "usage": S.budget.snapshot(),
        "plan": S.ledger.plan(),
        "hypotheses": S.ledger.hypotheses(),
        "report_accepted": S.report_markdown is not None,
        "injection_flags": S.injection_flags,
        "final_message": outcome.get("final"),
        "blocked_tool_calls": outcome.get("blocked_tool_calls", []),
        "tool_calls": calls,
    }
    (out / "agent-run.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    (out / "agent-trace.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    if S.findings_built:
        doc["findings"] = len(S.finding_set().findings)
        doc["explanations"] = _export_explanations(S, out, doc)
        (out / "agent-run.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
        (out / "agent-trace.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")
    return doc


def _export_explanations(S: Session, out, doc: dict) -> dict:  # noqa: N803
    from guardian.agents.gate import Explanation

    conn = connect(S.db)
    try:
        accepted = accepted_explanations(conn, S.run_id)
        rejected = conn.execute(
            "SELECT finding_id, attempt, reasons_json FROM explanations "
            "WHERE run_id = ? AND status = 'rejected' ORDER BY finding_id, attempt",
            (S.run_id,),
        ).fetchall()
    finally:
        conn.close()
    by_id = S.findings()
    order = list(by_id)
    items = []
    for fid in sorted(accepted, key=order.index):
        exp = Explanation.model_validate(accepted[fid])
        f = by_id[fid]
        explained = type(f).model_validate({**f.model_dump(), "rationale": exp.rationale()})
        items.append(
            {
                "finding_id": fid,
                "risk": f.risk.model_dump(mode="json") if f.risk else None,
                "explanation": exp.model_dump(mode="json"),
                "rationale": explained.rationale,
            }
        )
    payload = {
        "run_id": S.run_id,
        "provider": S.provider,
        "model": S.model,
        "generator": "language model",
        "accepted": items,
        "rejected": [
            {"finding_id": r[0], "attempt": r[1], "reasons": json.loads(r[2])} for r in rejected
        ],
        "blocked_tool_calls": doc["blocked_tool_calls"],
        "final_message": doc["final_message"],
    }
    (out / "explanations.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        f"# AI explanations: {S.run_id}",
        "",
        f"Generator: **language model** ({S.provider}:{S.model}). Each explanation passed the "
        "deterministic gate; rejected ones are listed, never shown as explanations.",
        "",
    ]
    for item in items:
        f, e, r = by_id[item["finding_id"]], item["explanation"], item["risk"] or {}
        lines += [
            f"## {f.id} {f.title}",
            "",
            f"- Risk: {r.get('score')} {r.get('level')} (coverage {r.get('weight_coverage')})",
            f"- Why it matters: {e['why_it_matters']}",
            f"- Reachability: {e['reachability']}",
            f"- Confidence: {e['confidence']} ({e['confidence_reason']})",
            f"- Evidence: {', '.join(e['cited_evidence'])}",
            "",
        ]
    (out / "explanations.md").write_text("\n".join(lines) + "\n")
    return {"accepted": len(items), "rejected": len(rejected)}
