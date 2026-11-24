"""Read-only views for the UI: the dependency-graph overview, the SBOM and the agent timeline.

Pure functions over the evidence store and the run directory. Nothing here writes.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from itertools import pairwise
from pathlib import Path

from guardian.schemas.graph import DependencyGraph
from guardian.schemas.sbom import DependencyScope

RISK_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
RANK_LEVEL = {v: k for k, v in RISK_RANK.items()}
MAX_GRAPH_NODES = 400
MAX_PAGE = 200


def findings_by_label(conn: sqlite3.Connection, run: str) -> dict[str, tuple[int, int]]:
    """name@version -> (highest risk rank, number of findings) for a stored run."""
    out: dict[str, tuple[int, int]] = {}
    rows = conn.execute(
        "SELECT component_name, component_version, risk_level, COUNT(*) FROM findings "
        "WHERE run_id = ? GROUP BY component_name, component_version, risk_level",
        (run,),
    )
    for name, version, level, count in rows:
        label = f"{name}@{version}" if version else name
        rank, total = out.get(label, (0, 0))
        out[label] = (max(rank, RISK_RANK.get(level or "", 0)), total + count)
    return out


# --- dependency graph overview ---------------------------------------------------------------


def graph_overview(
    g: DependencyGraph,
    by_label: dict[str, tuple[int, int]],
    *,
    scope: str = "runtime",
    min_risk: str | None = None,
    q: str | None = None,
    limit: int = 160,
) -> dict:
    """A readable subgraph: the app, its direct dependencies and every vulnerable package, each
    drawn with its path from the root. ``q`` or ``min_risk`` change which packages are focused.
    The full 1,000+ node graph is not drawable; ``truncated`` says when nodes were left out."""
    runtime_only = scope == "runtime"
    limit = max(20, min(limit, MAX_GRAPH_NODES))
    depths = g.depths()
    floor = RISK_RANK.get(min_risk or "", 0)
    needle = (q or "").strip().lower()

    candidates = []
    for n in g.nodes:
        if n.bom_ref == g.root or (runtime_only and n.scope is DependencyScope.DEV):
            continue
        label = g.label(n.bom_ref)
        rank, count = by_label.get(label, (0, 0))
        if needle and needle not in n.component.name.lower():
            continue
        if rank < floor:
            continue
        if not needle and not floor and not (n.direct or count):
            continue  # default focus: direct dependencies and anything with a finding
        candidates.append(
            (-rank, 0 if n.direct else 1, depths.get(n.bom_ref, 99), label, n.bom_ref)
        )
    candidates.sort()

    keep: dict[str, bool] = {g.root: False}  # node id -> is a focus node
    edges: set[tuple[str, str]] = set()
    skipped = 0
    for *_, node in candidates:
        path = g.shortest_path(node, exclude_dev=runtime_only) or g.shortest_path(node)
        if not path:
            skipped += 1
            continue
        added = [p for p in path if p not in keep]
        if len(keep) + len(added) > limit:
            skipped += 1
            continue
        for p in added:
            keep[p] = False
        keep[node] = True
        edges.update(pairwise(path))

    nodes = []
    for node_id in keep:
        n = g.node(node_id)
        label = g.label(node_id)
        rank, count = by_label.get(label, (0, 0))
        role = "root" if node_id == g.root else "direct" if n.direct else "transitive"
        nodes.append(
            {
                "data": {
                    "id": node_id,
                    "label": label,
                    "name": n.component.name,
                    "version": n.component.version,
                    "scope": n.scope.value,
                    "role": role,
                    "depth": depths.get(node_id, 0),
                    "risk": RANK_LEVEL.get(rank, "None"),
                    "findings": count,
                    "focus": keep[node_id],
                }
            }
        )
    edge_rows = [{"data": {"id": f"{a}->{b}", "source": a, "target": b}} for a, b in sorted(edges)]
    total = sum(
        1
        for n in g.nodes
        if n.bom_ref != g.root and not (runtime_only and n.scope is DependencyScope.DEV)
    )
    return {
        "nodes": nodes,
        "edges": edge_rows,
        "stats": {
            "scope": scope,
            "shown_nodes": len(nodes) - 1,
            "total_nodes": total,
            "focus_candidates": len(candidates),
            "focus_skipped": skipped,
            "truncated": skipped > 0,
        },
    }


# --- SBOM -------------------------------------------------------------------------------------


def _licenses(component: dict) -> list[str]:
    out = []
    for entry in component.get("licenses", []):
        lic = entry.get("license") or {}
        value = lic.get("id") or lic.get("name") or entry.get("expression")
        if value:
            out.append(str(value))
    return out


def load_sbom(path: Path) -> dict:
    """Parse the run's CycloneDX document into display rows and summary counts."""
    doc = json.loads(path.read_text())
    props = lambda c: {p.get("name"): p.get("value") for p in c.get("properties", [])}  # noqa: E731
    rows = []
    for c in doc.get("components", []):
        p = props(c)
        purl = c.get("purl") or ""
        eco = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else None
        version = c.get("version")
        rows.append(
            {
                "bom_ref": c.get("bom-ref"),
                "type": c.get("type"),
                "name": c.get("name", ""),
                "version": version,
                "label": f"{c.get('name', '')}@{version}" if version else c.get("name", ""),
                "purl": purl or None,
                "ecosystem": eco,
                "licenses": _licenses(c),
                "found_by": p.get("syft:package:foundBy"),
                "location": p.get("syft:location:0:path"),
            }
        )
    meta = doc.get("metadata", {})
    tools = meta.get("tools", {})
    tool_list = tools.get("components", []) if isinstance(tools, dict) else tools
    return {
        "document": {
            "format": doc.get("bomFormat"),
            "spec_version": doc.get("specVersion"),
            "serial_number": doc.get("serialNumber"),
            "version": doc.get("version"),
            "timestamp": meta.get("timestamp"),
            "tools": [f"{t.get('name')} {t.get('version', '')}".strip() for t in tool_list],
            "subject": Path((meta.get("component") or {}).get("name") or "").name or None,
            "components": len(rows),
            "dependency_records": len(doc.get("dependencies", [])),
        },
        "rows": rows,
    }


def sbom_view(
    sbom: dict,
    by_label: dict[str, tuple[int, int]],
    *,
    q: str | None = None,
    type_: str | None = None,
    ecosystem: str | None = None,
    vulnerable_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    rows = []
    for r in sbom["rows"]:
        rank, count = by_label.get(r["label"], (0, 0))
        rows.append({**r, "risk": RANK_LEVEL.get(rank, "None"), "findings": count, "_rank": rank})
    summary = {
        "by_type": dict(Counter(r["type"] for r in rows)),
        "by_ecosystem": dict(Counter(r["ecosystem"] or "none" for r in rows)),
        "top_licenses": dict(
            Counter(lic for r in rows for lic in (r["licenses"] or ["unspecified"])).most_common(8)
        ),
        "with_findings": sum(1 for r in rows if r["findings"]),
    }
    needle = (q or "").strip().lower()
    rows = [
        r
        for r in rows
        if (not needle or needle in r["name"].lower() or needle in (r["purl"] or "").lower())
        and (not type_ or r["type"] == type_)
        and (not ecosystem or (r["ecosystem"] or "none") == ecosystem)
        and (not vulnerable_only or r["findings"])
    ]
    rows.sort(key=lambda r: (-r["_rank"], -r["findings"], r["name"], r["version"] or ""))
    limit = max(1, min(limit, MAX_PAGE))
    page = [{k: v for k, v in r.items() if k != "_rank"} for r in rows[offset : offset + limit]]
    return {
        "document": sbom["document"],
        "summary": summary,
        "total": len(rows),
        "items": page,
    }


# --- agent timeline -----------------------------------------------------------------------


def agent_timeline(conn: sqlite3.Connection, run: str, after: int = 0, limit: int = 300) -> dict:
    """The newest agent run for a run directory: status, budget, plan, hypotheses and events.

    Works while the run is still going (it is linked to its run directory at start), so the UI
    can poll with ``after`` set to the last sequence number it has seen.
    """
    row = conn.execute(
        "SELECT agent_run_id, goal, target, provider, model, status, stop_reason, budget_json, "
        "usage_json, started_at, finished_at, report_md IS NOT NULL FROM agent_runs "
        "WHERE run_id = ? ORDER BY started_at DESC LIMIT 1",
        (run,),
    ).fetchone()
    if row is None:
        return {"agent_run": None, "events": [], "plan": [], "hypotheses": [], "last_seq": 0}
    rid = row[0]
    keys = (
        "id",
        "goal",
        "target",
        "provider",
        "model",
        "status",
        "stop_reason",
        "budget",
        "usage",
        "started_at",
        "finished_at",
        "has_report",
    )
    info = dict(zip(keys, row, strict=True))
    info["budget"] = json.loads(info["budget"] or "{}")
    info["usage"] = json.loads(info["usage"]) if info["usage"] else None
    info["has_report"] = bool(info["has_report"])

    agg = conn.execute(
        "SELECT SUM(kind = 'model_call'), SUM(kind IN ('tool_call', 'delegate', 'tool_error')), "
        "SUM(json_extract(payload_json, '$.tokens_in')), "
        "SUM(json_extract(payload_json, '$.tokens_out')), MAX(seq) "
        "FROM agent_events WHERE agent_run_id = ?",
        (rid,),
    ).fetchone()
    info["live_usage"] = {
        "steps": agg[0] or 0,
        "tool_calls": agg[1] or 0,
        "tokens": int((agg[2] or 0) + (agg[3] or 0)),
    }
    limit = max(1, min(limit, 500))
    events = [
        {"seq": s, "ts": ts, "agent": a, "kind": k, "name": n, "payload": json.loads(p)}
        for s, ts, a, k, n, p in conn.execute(
            "SELECT seq, ts, agent, kind, name, payload_json FROM agent_events "
            "WHERE agent_run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
            (rid, max(0, after), limit),
        )
    ]
    plan = [
        {"id": i, "goal": g, "status": st, "assigned_agent": ag, "rationale": ra}
        for i, g, st, ag, ra in conn.execute(
            "SELECT id, goal, status, assigned_agent, rationale FROM plan_items "
            "WHERE agent_run_id = ? ORDER BY id",
            (rid,),
        )
    ]
    hypotheses = [
        {
            "id": i,
            "author": au,
            "claim": c,
            "kind": k,
            "confidence": cf,
            "status": st,
            "reasons": json.loads(rs),
            "finding_ids": json.loads(fi),
        }
        for i, au, c, k, cf, st, rs, fi in conn.execute(
            "SELECT id, author, claim, kind, confidence, status, reasons_json, finding_ids_json "
            "FROM hypotheses WHERE agent_run_id = ? ORDER BY id",
            (rid,),
        )
    ]
    return {
        "agent_run": info,
        "events": events,
        "plan": plan,
        "hypotheses": hypotheses,
        "last_seq": agg[4] or 0,
        "live": info["status"] == "running",
    }
