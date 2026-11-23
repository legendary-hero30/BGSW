"""D1.S9: HTTP API over the SQLite evidence store, plus the built UI.

* Reads only, except one controlled POST that starts a scan of a user-supplied GitHub repo.
* No CORS, served on loopback. The store is opened read-only (SQLite mode=ro).
* Runs must exist in the store before any of their files are read (no path from the client).
* Strict security headers. Repository-derived text is returned as data; the UI escapes it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from functools import lru_cache
from itertools import pairwise
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian.agents.trace import build_steps
from guardian.api.jobs import run_repo_job
from guardian.checklist import as_dict, evaluate
from guardian.schemas.evidence import EvidenceKind
from guardian.schemas.finding import Finding
from guardian.schemas.graph import DependencyGraph, EdgeKind, GraphEdge
from guardian.schemas.sbom import Component, DependencyScope, SbomComponent
from guardian.store import DEFAULT_DB, connect_readonly
from guardian.targets import DynamicTargetError, parse_repo
from guardian.tools.runner import WORKSPACE, jail

UI_DIST = WORKSPACE / "ui" / "dist"
MAX_LIMIT = 500
MAX_JOBS = 50
CONTEXT_PARENTS = 10
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)


class StartRun(BaseModel):
    repo: str = Field(min_length=1, max_length=200)


# Constant SQL only: optional filters use "? IS NULL OR ..." so no query text is built at runtime.
FINDINGS_SELECT = (
    "SELECT f.id, f.type, f.title, f.component_name, f.component_version, f.severity, "
    "f.risk_score, f.risk_level, f.weight_coverage, f.override, "
    "EXISTS (SELECT 1 FROM explanations e WHERE e.run_id = f.run_id "
    "AND e.finding_id = f.id AND e.status = 'accepted')"
)
FINDINGS_FILTER = (
    "FROM findings f WHERE f.run_id = ? AND (? IS NULL OR f.type = ?) "
    "AND (? IS NULL OR f.risk_level = ?) AND (? IS NULL OR f.component_name LIKE ? ESCAPE '\\' "
    "OR f.title LIKE ? ESCAPE '\\')"
)
EVIDENCE_OF_FINDING = (
    "SELECT e.record_json FROM finding_evidence fe JOIN evidence e "
    "ON e.run_id = fe.run_id AND e.id = fe.evidence_id "
    "WHERE fe.run_id = ? AND fe.finding_id = ? ORDER BY fe.position"
)
GRAPH_NODE_OF_FINDING = (
    "SELECT e.graph_node FROM finding_evidence fe JOIN evidence e "
    "ON e.run_id = fe.run_id AND e.id = fe.evidence_id "
    "WHERE fe.run_id = ? AND fe.finding_id = ? AND e.kind = ? ORDER BY fe.position LIMIT 1"
)


def create_app(
    db: str = DEFAULT_DB,
    ui_dir: Path = UI_DIST,
    job_runner: Callable[[dict, str, str], None] | None = None,
) -> FastAPI:
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guardian-job")
    jobs: dict[str, dict] = {}
    runner = job_runner or run_repo_job

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="Supply Chain Guardian",
        description="Read-only evidence API; POST /api/runs starts one scanned GitHub repo.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    conn = connect_readonly(db)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        allowed_post = request.method == "POST" and request.url.path == "/api/runs"
        if request.method not in {"GET", "HEAD"} and not allowed_post:
            return JSONResponse({"detail": "read-only API"}, status_code=405)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def known_run(run: str) -> str:
        row = conn.execute("SELECT run_id FROM runs WHERE run_id = ?", (run,)).fetchone()
        if row is None:
            raise HTTPException(404, "unknown run")
        return row[0]

    def finding(run: str, fid: str) -> Finding:
        row = conn.execute(
            "SELECT finding_json FROM findings WHERE run_id = ? AND id = ?", (run, fid)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "unknown finding")
        return Finding.model_validate_json(row[0])

    @lru_cache(maxsize=8)
    def graph(run: str) -> DependencyGraph:
        nodes = tuple(
            SbomComponent(
                bom_ref=r[0],
                component=Component(name=r[1], version=r[2]),
                scope=DependencyScope(r[3]),
                direct=None if r[4] is None else bool(r[4]),
                optional=bool(r[5]),
            )
            for r in conn.execute(
                "SELECT node_id, name, version, scope, direct, optional "
                "FROM graph_nodes WHERE run_id = ?",
                (run,),
            )
        )
        edges = tuple(
            GraphEdge(source=r[0], target=r[1], kind=EdgeKind(r[2]))
            for r in conn.execute(
                "SELECT source, target, kind FROM graph_edges WHERE run_id = ?", (run,)
            )
        )
        root = "." if any(n.bom_ref == "." for n in nodes) else nodes[0].bom_ref
        return DependencyGraph(root=root, nodes=nodes, edges=edges)

    @app.get("/api/runs")
    def runs() -> list[dict]:
        out = []
        for run_id, target, commit, generated, synthetic, summary in conn.execute(
            "SELECT run_id, target, commit_sha, generated_at, synthetic, summary_json FROM runs "
            "ORDER BY generated_at DESC"
        ):
            s = json.loads(summary)
            out.append(
                {
                    "run_id": run_id,
                    "target": target,
                    "commit": commit,
                    "generated_at": generated,
                    "synthetic": bool(synthetic),
                    "findings": s.get("findings"),
                    "by_risk_level": s.get("by_risk_level"),
                    "by_type": s.get("by_type"),
                }
            )
        return out

    @app.post("/api/runs", status_code=202)
    def start_run(body: StartRun) -> dict:
        """Queue one scan of a user-supplied GitHub npm repository (the only write endpoint)."""
        try:
            parse_repo(body.repo)
        except DynamicTargetError as exc:
            raise HTTPException(400, str(exc)) from exc
        job = {
            "id": uuid4().hex,
            "repo": body.repo.strip(),
            "status": "queued",
            "step": "Queued",
            "run_id": None,
            "error": None,
            "steps": [],
            "accepted": 0,
            "rejected": 0,
            "blocked": 0,
            "findings": None,
            "created": datetime.now(UTC).isoformat(timespec="seconds"),
            "finished": None,
        }
        jobs[job["id"]] = job
        while len(jobs) > MAX_JOBS:
            jobs.pop(next(iter(jobs)), None)
        snapshot = dict(job)  # the worker may finish before this response is serialised
        executor.submit(runner, job, job["repo"], db)
        return snapshot

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> dict:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown job")
        return dict(job)

    @app.get("/api/summary")
    def summary(run: str) -> dict:
        row = conn.execute(
            "SELECT summary_json FROM runs WHERE run_id = ?", (known_run(run),)
        ).fetchone()
        return json.loads(row[0])

    @app.get("/api/findings")
    def findings(
        run: str,
        type: str | None = None,
        level: str | None = None,
        q: str | None = Query(None, max_length=100),
        limit: int = Query(100, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
    ) -> dict:
        run = known_run(run)
        pattern = None
        if q:
            escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
        args = (run, type, type, level, level, pattern, pattern, pattern)
        total = conn.execute(f"SELECT COUNT(*) {FINDINGS_FILTER}", args).fetchone()[0]
        rows = conn.execute(
            f"{FINDINGS_SELECT} {FINDINGS_FILTER} ORDER BY f.ordinal LIMIT ? OFFSET ?",
            (*args, limit, offset),
        ).fetchall()
        keys = (
            "id",
            "type",
            "title",
            "component",
            "version",
            "severity",
            "risk_score",
            "risk_level",
            "coverage",
            "override",
            "explained",
        )
        items = [{**dict(zip(keys, r, strict=True)), "explained": bool(r[10])} for r in rows]
        return {"total": total, "items": items}

    @app.get("/api/findings/{fid}")
    def finding_detail(fid: str, run: str) -> dict:
        run = known_run(run)
        f = finding(run, fid)
        evidence = [json.loads(r[0]) for r in conn.execute(EVIDENCE_OF_FINDING, (run, fid))]
        exp_row = conn.execute(
            "SELECT explanation_json, provider, model FROM explanations WHERE run_id = ? AND "
            "finding_id = ? AND status = 'accepted' ORDER BY attempt DESC LIMIT 1",
            (run, fid),
        ).fetchone()
        rejected = conn.execute(
            "SELECT COUNT(*) FROM explanations WHERE run_id = ? AND finding_id = ? "
            "AND status = 'rejected'",
            (run, fid),
        ).fetchone()[0]
        explanation = None
        if exp_row:
            provider = exp_row[1]
            explanation = {
                **json.loads(exp_row[0]),
                "provider": provider,
                "model": exp_row[2],
                "generator": "language model",
            }
        return {
            "finding": json.loads(f.model_dump_json()),
            "evidence": evidence,
            "explanation": explanation,
            "rejected_explanations": rejected,
        }

    @app.get("/api/graph/{fid}")
    def finding_graph(fid: str, run: str) -> dict:
        """Cytoscape elements: the finding's path (flagged) plus other parents of the package."""
        run = known_run(run)
        f = finding(run, fid)
        row = conn.execute(
            GRAPH_NODE_OF_FINDING, (run, fid, EvidenceKind.GRAPH_NODE.value)
        ).fetchone()
        graph_node = row[0] if row else None
        if graph_node is None:  # image/config findings: draw the recorded path as a chain
            labels = list(f.dependency_path)
            nodes = [
                {
                    "data": {
                        "id": f"p{i}",
                        "label": label,
                        "on_path": True,
                        "role": "root"
                        if i == 0
                        else ("target" if i == len(labels) - 1 else "path"),
                    }
                }
                for i, label in enumerate(labels)
            ]
            edges = [
                {"data": {"id": f"e{i}", "source": f"p{i}", "target": f"p{i + 1}", "on_path": True}}
                for i in range(len(labels) - 1)
            ]
            return {"nodes": nodes, "edges": edges, "source": "recorded path"}
        g = graph(run)
        runtime = g.node(graph_node).scope is not DependencyScope.DEV
        path = (runtime and g.shortest_path(graph_node, exclude_dev=True)) or g.shortest_path(
            graph_node
        )
        path = list(path or [graph_node])
        on_path = set(path)
        parents = [e.source for e in g.edges if e.target == graph_node and e.source not in on_path]
        keep = list(dict.fromkeys([*path, *parents[:CONTEXT_PARENTS]]))
        nodes = []
        for node_id in keep:
            n = g.node(node_id)
            role = (
                "root"
                if node_id == g.root
                else "target"
                if node_id == graph_node
                else "path"
                if node_id in on_path
                else "context"
            )
            nodes.append(
                {
                    "data": {
                        "id": node_id,
                        "label": g.label(node_id),
                        "role": role,
                        "scope": n.scope.value,
                        "direct": n.direct,
                        "on_path": node_id in on_path,
                    }
                }
            )
        pairs = set(pairwise(path))
        edges = [
            {
                "data": {
                    "id": f"{e.source}->{e.target}",
                    "source": e.source,
                    "target": e.target,
                    "kind": e.kind.value,
                    "on_path": (e.source, e.target) in pairs,
                }
            }
            for e in g.edges
            if e.source in keep
            and e.target in keep
            and ((e.source, e.target) in pairs or e.target == graph_node)
        ]
        return {
            "nodes": nodes,
            "edges": edges,
            "source": "dependency graph",
            "other_parents": max(0, len(parents) - CONTEXT_PARENTS),
        }

    @app.get("/api/agent-steps")
    def agent_steps(run: str) -> dict:
        """The recorded agent tool calls for a run, grouped for the Agent Steps view."""
        run = known_run(run)
        trace: dict = {}
        trace_path = jail(run) / "agent-trace.json"
        if trace_path.exists():
            try:
                trace = json.loads(trace_path.read_text())
            except json.JSONDecodeError:
                trace = {}
        doc: dict = {}
        doc_path = jail(run) / "explanations.json"
        if doc_path.exists():
            try:
                doc = json.loads(doc_path.read_text())
            except json.JSONDecodeError:
                doc = {}
        provider = trace.get("provider") or doc.get("provider")
        if provider in {"scripted", "scripted-hallucinating"}:
            # Legacy offline fixtures are not part of the product; never show them as agent work.
            trace, doc = {}, {}
        calls = trace.get("tool_calls") if isinstance(trace.get("tool_calls"), list) else []
        accepted = doc.get("accepted") if isinstance(doc.get("accepted"), list) else []
        rejected = doc.get("rejected") if isinstance(doc.get("rejected"), list) else []
        blocked = trace.get("blocked_tool_calls") or doc.get("blocked_tool_calls") or []
        return {
            "run_id": run,
            "provider": trace.get("provider") or doc.get("provider"),
            "model": trace.get("model") or doc.get("model"),
            "generator": "language model" if calls else None,
            "steps": build_steps(calls),
            "counts": {
                "tool_calls": len(calls),
                "accepted": len(accepted),
                "rejected": len(rejected),
                "blocked": len(blocked),
            },
            "final_message": trace.get("final_message") or doc.get("final_message"),
        }

    @app.get("/api/checklist")
    def checklist(run: str) -> dict:
        return as_dict(evaluate(known_run(run), db))

    if (ui_dir / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=ui_dir / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(ui_dir / "index.html")

    return app
