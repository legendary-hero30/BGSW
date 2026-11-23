"""Run artefacts for the gated explanations: explanations.json/.md and agent-trace.json."""

from __future__ import annotations

import json

from guardian.agents.gate import Explanation
from guardian.agents.models import ModelConfig
from guardian.agents.tools import AgentContext, write_trace
from guardian.store import accepted_explanations, connect, load_findings
from guardian.tools.runner import jail


def export(ctx: AgentContext, cfg: ModelConfig, outcome: dict) -> dict:
    """Write explanations.json/.md for the run. Every rationale is re-validated on Finding."""
    out = jail(ctx.out_dir)
    conn = connect(ctx.db)
    try:
        fs = load_findings(conn, ctx.run_id)
        accepted = accepted_explanations(conn, ctx.run_id)
        rejected = conn.execute(
            "SELECT finding_id, attempt, reasons_json FROM explanations "
            "WHERE run_id = ? AND status = 'rejected' ORDER BY finding_id, attempt",
            (ctx.run_id,),
        ).fetchall()
    finally:
        conn.close()
    by_id = {f.id: f for f in fs.findings}
    order = [f.id for f in fs.findings]
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
    doc = {
        "run_id": ctx.run_id,
        "provider": cfg.provider,
        "model": cfg.model,
        "generator": "language model",
        "accepted": items,
        "rejected": [
            {"finding_id": r[0], "attempt": r[1], "reasons": json.loads(r[2])} for r in rejected
        ],
        "blocked_tool_calls": outcome["blocked_tool_calls"],
        "final_message": outcome["final"],
    }
    (out / "explanations.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "explanations.md").write_text(render(doc, by_id))
    write_trace(
        ctx,
        out / "agent-trace.json",
        {
            "provider": cfg.provider,
            "model": cfg.model,
            "generator": "language model",
            "blocked_tool_calls": outcome["blocked_tool_calls"],
            "final_message": outcome["final"],
        },
    )
    return doc


def render(doc: dict, by_id: dict) -> str:
    lines = [
        f"# AI explanations: {doc['run_id']}",
        "",
        f"Generator: **{doc['generator']}** ({doc['provider']}:{doc['model']}). Each "
        "explanation passed the deterministic gate; rejected ones are listed, never shown "
        "as explanations.",
        "",
    ]
    for item in doc["accepted"]:
        f, e, r = by_id[item["finding_id"]], item["explanation"], item["risk"] or {}
        lines += [
            f"## {f.id} {f.title}",
            "",
            f"- Risk: {r.get('score')} {r.get('level')} (coverage {r.get('weight_coverage')})",
            f"- Path: {' > '.join(f.dependency_path) or 'n/a'}",
            f"- Why it matters: {e['why_it_matters']}",
            f"- Reachability: {e['reachability']}",
            f"- Confidence: {e['confidence']} ({e['confidence_reason']})",
            f"- Evidence: {', '.join(e['cited_evidence'])}",
            "",
        ]
    if doc["rejected"]:
        lines += ["## Rejected by the gate", ""]
        lines += [
            f"- {r['finding_id']} attempt {r['attempt']}: {'; '.join(r['reasons'])}"
            for r in doc["rejected"]
        ]
    return "\n".join(lines) + "\n"
