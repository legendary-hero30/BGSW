"""D1.S9: HTTP API over the SQLite evidence store, plus the built UI.

* Reads only, except one controlled POST that starts a scan of a user-supplied GitHub repo.
* No CORS, served on loopback. The store is opened read-only (SQLite mode=ro).
* Runs must exist in the store before any of their files are read (no path from the client).
* Strict security headers. Repository-derived text is returned as data; the UI escapes it.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from functools import lru_cache
from itertools import pairwise
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator

from guardian.agents.trace import summarize
from guardian.api.jobs import GOALS, run_repo_job
from guardian.api.views import (
    agent_timeline,
    findings_by_label,
    graph_overview,
    load_sbom,
    sbom_view,
)
from guardian.checklist import as_dict, evaluate
from guardian.remediation import proposals as props
from guardian.remediation import service as remediation
from guardian.remediation.export import export_fix
from guardian.remediation.push import PushError, push_fix
from guardian.remediation.push import allowed as push_allowed
from guardian.schemas.evidence import EvidenceKind
from guardian.schemas.finding import Finding
from guardian.schemas.graph import DependencyGraph, EdgeKind, GraphEdge
from guardian.schemas.sbom import Component, DependencyScope, SbomComponent
from guardian.scoring.confidence import finding_confidence
from guardian.store import DEFAULT_DB, connect, connect_readonly
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


# Read-only SQLite access with one connection per thread (a shared one broke under polling).
class ThreadLocalReader:
    """One read-only connection per worker thread. A single shared sqlite3 connection used by
    the server's thread pool raised "bad parameter or other API misuse" under concurrent
    requests (seen in the browser: the page polls several endpoints at once)."""

    def __init__(self, db: str) -> None:
        self.db = db
        self.local = threading.local()

    def execute(self, sql: str, params: tuple | list = ()):
        c = getattr(self.local, "conn", None)
        if c is None:
            c = self.local.conn = connect_readonly(self.db)
        return c.execute(sql, params)


# Body of POST /api/runs: a repo URL (or the demo) plus the goal and optional branch.
class StartRun(BaseModel):
    repo: str = Field(default="", max_length=200)
    demo: bool = False  # the bundled demo app instead of a GitHub repository
    goal: Literal["assess", "remediate"] = "remediate"
    custom_goal: str | None = Field(default=None, max_length=800)
    branch: str | None = Field(
        default=None, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"
    )

    @model_validator(mode="after")
    def needs_a_target(self) -> StartRun:
        if not self.demo and not self.repo.strip():
            raise ValueError("give a GitHub repository or choose the demo app")
        return self


# Body of approve/reject: who decided, and an optional note that is logged.
class Decision(BaseModel):
    run: str = Field(min_length=1, max_length=200)
    approver: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=500)


# Body of validate/export/push: just the run (push also carries confirm_repo).
class RunRef(BaseModel):
    model_config = ConfigDict(extra="allow")  # push carries confirm_repo
    run: str = Field(min_length=1, max_length=200)


# Only loopback Host headers are served, so the approval routes are not reachable from the network.
LOOPBACK_HOST = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$")
# Proposal ids look like R-001; anything else is a 404.
PROPOSAL_ID = re.compile(r"^R-\d{3,6}$")
# The routes that change state; they need the per-server approval token.
WRITE_PATH = re.compile(r"^/api/proposals/R-\d{3,6}/(approve|reject|validate|export|push)$")


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


# Build the FastAPI app: read-only views of a run, plus the few gated write routes.
def create_app(
    db: str = DEFAULT_DB,
    ui_dir: Path = UI_DIST,
    job_runner: Callable[[dict, str, str], None] | None = None,
) -> FastAPI:
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guardian-job")
    validator = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guardian-validate")
    validating: dict[str, dict] = {}
    approval_token = secrets.token_urlsafe(32)  # per server process; handed to the same-origin UI
    jobs: dict[str, dict] = {}
    runner = job_runner or run_repo_job

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        executor.shutdown(wait=False, cancel_futures=True)
        validator.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="Supply Chain Guardian",
        description="Read-only evidence API; POST /api/runs starts one scanned GitHub repo.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    conn = ThreadLocalReader(db)
    sbom_cache: dict[str, tuple[int, dict]] = {}

    # Reject non-loopback hosts and require the approval token on write routes.
    @app.middleware("http")
    async def headers(request: Request, call_next):
        path = request.url.path
        host = request.headers.get("host", "")
        write = request.method == "POST" and bool(WRITE_PATH.match(path))
        allowed_post = (request.method == "POST" and path == "/api/runs") or write
        if request.method not in {"GET", "HEAD"} and not allowed_post:
            return JSONResponse({"detail": "read-only API"}, status_code=405)
        if write or path == "/api/approval-token":
            # DNS-rebinding and cross-site defence for the approval gate.
            origin = request.headers.get("origin")
            if not LOOPBACK_HOST.match(host) or (origin and urlparse(origin).netloc != host):
                return JSONResponse({"detail": "forbidden origin"}, status_code=403)
            if write and not secrets.compare_digest(
                request.headers.get("x-guardian-approval", ""), approval_token
            ):
                return JSONResponse({"detail": "missing or wrong approval token"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    # Return the run id only if it is stored, else 404.
    def known_run(run: str) -> str:
        row = conn.execute("SELECT run_id FROM runs WHERE run_id = ?", (run,)).fetchone()
        if row is None:
            raise HTTPException(404, "unknown run")
        return row[0]

    # Load one stored finding by id.
    def finding(run: str, fid: str) -> Finding:
        row = conn.execute(
            "SELECT finding_json FROM findings WHERE run_id = ? AND id = ?", (run, fid)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "unknown finding")
        return Finding.model_validate_json(row[0])

    @lru_cache(maxsize=8)
    # Load the dependency graph of a run from its run directory (cached).
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

    # List stored runs, newest first.
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

    # Queue a scan job. Only repo URL, demo flag, goal and branch are accepted.
    @app.post("/api/runs", status_code=202)
    def start_run(body: StartRun) -> dict:
        """Queue one scan of a user-supplied GitHub npm repository (the only write endpoint)."""
        if not body.demo:
            try:
                parse_repo(body.repo)
            except DynamicTargetError as exc:
                raise HTTPException(400, str(exc)) from exc
        goal_text = (body.custom_goal or "").strip() or GOALS[body.goal]
        job = {
            "id": uuid4().hex,
            "repo": "bundled demo app" if body.demo else body.repo.strip(),
            "demo": body.demo,
            "branch": body.branch,
            "lockfile_origin": None,  # repository | generated | upgraded, set after the clone
            "goal_text": goal_text,
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

    # Tell the UI what this server can do now (agents, validation, sandbox, push).
    @app.get("/api/capabilities")
    def capabilities() -> dict:
        """What this server can do right now, so the UI can say what is missing."""
        from guardian.remediation import lockfile
        from guardian.sandbox import BwrapSandbox

        key = bool(os.environ.get("DEEPINFRA_API_KEY"))
        allowed = os.environ.get("GUARDIAN_ALLOW_EXTERNAL_MODELS") == "1"
        sandbox_ok, sandbox_why = BwrapSandbox().available()
        return {
            "agents": {
                "ready": key and allowed,
                "detail": "DeepInfra key set and external models allowed"
                if key and allowed
                else "missing "
                + " and ".join(
                    m
                    for m, ok in (
                        ("DEEPINFRA_API_KEY (empty or absent in .env and the environment)", key),
                        ("GUARDIAN_ALLOW_EXTERNAL_MODELS=1", allowed),
                    )
                    if not ok
                )
                + ". Set them in .env and restart the server; without them runs are scanner-only",
            },
            "validation": {
                "ready": lockfile.allowed(),
                "detail": "npm registry access allowed for the lockfile and install steps"
                if lockfile.allowed()
                else "set GUARDIAN_ALLOW_REGISTRY_ACCESS=1 to let validation regenerate lockfiles",
            },
            "sandbox": {"ready": sandbox_ok, "detail": sandbox_why},
            "push": {
                "ready": push_allowed(),
                "detail": "push enabled (token set); new guardian/fix-* branches only"
                if push_allowed()
                else "set GUARDIAN_ALLOW_PUSH=1 and GUARDIAN_GITHUB_TOKEN in .env to let the "
                "server push",
            },
        }

    # Poll one scan job: status, current step, live agent steps.
    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> dict:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown job")
        return dict(job)

    # Counts for the overview tab.
    @app.get("/api/summary")
    def summary(run: str) -> dict:
        row = conn.execute(
            "SELECT summary_json FROM runs WHERE run_id = ?", (known_run(run),)
        ).fetchone()
        return json.loads(row[0])

    # Ranked findings with optional type, level and text filters.
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

    # One finding with its score breakdown, evidence and accepted explanation.
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
            "confidence": dict(zip(("level", "reasons"), finding_confidence(f), strict=True)),
        }

    # The dependency path from the app to this finding's package.
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

    # Summary of what each agent did in a run.
    @app.get("/api/agent-steps")
    def agent_steps(run: str) -> dict:
        """The recorded agent run for a stored run: plan, steps, hypotheses, budget, status."""
        run = known_run(run)
        trace: dict = {}
        trace_path = jail(run) / "agent-run.json"
        if trace_path.exists():
            try:
                trace = json.loads(trace_path.read_text())
            except json.JSONDecodeError:
                trace = {}
        out = summarize(trace)
        doc: dict = {}
        doc_path = jail(run) / "explanations.json"
        if doc_path.exists():
            try:
                doc = json.loads(doc_path.read_text())
            except json.JSONDecodeError:
                doc = {}
        accepted = doc.get("accepted") if isinstance(doc.get("accepted"), list) else []
        rejected = doc.get("rejected") if isinstance(doc.get("rejected"), list) else []
        out["run_id"] = run
        out["counts"].update({"accepted": len(accepted), "rejected": len(rejected)})
        return out

    # -- remediation: proposals, human approval gate, validation ---------------------------------
    @app.get("/api/approval-token")
    def approval_token_endpoint() -> dict:
        """Same-origin only (no CORS, loopback Host required). Approving needs this token and a
        named approver; agents have no route to either."""
        return {"token": approval_token}

    def stored_run(run: str) -> str:
        fresh = connect_readonly(db)
        try:
            row = fresh.execute("SELECT run_id FROM runs WHERE run_id = ?", (run,)).fetchone()
        finally:
            fresh.close()
        if row is None:
            raise HTTPException(404, "unknown run")
        return row[0]

    # Fix proposals of a run (empty while the agents are still working).
    @app.get("/api/proposals")
    def proposals(run: str = Query(min_length=1, max_length=200)) -> dict:
        fresh = connect_readonly(db)
        known = fresh.execute("SELECT 1 FROM runs WHERE run_id = ?", (run,)).fetchone()
        fresh.close()
        if known is None:  # the agents are still working: nothing is stored yet, not an error
            return {"run_id": run, "proposals": []}
        fresh = connect_readonly(db)
        try:
            rows = [remediation.view(fresh, run, p.id) for p in props.list_proposals(fresh, run)]
        finally:
            fresh.close()
        for r in rows:
            r["validating"] = validating.get(f"{run}:{r['id']}")
        return {"run_id": run, "proposals": rows}

    # One proposal with full approval and validation history.
    @app.get("/api/proposals/{pid}")
    def proposal(pid: str, run: str = Query(min_length=1, max_length=200)) -> dict:
        if not PROPOSAL_ID.match(pid):
            raise HTTPException(404, "unknown proposal")
        stored_run(run)
        fresh = connect_readonly(db)
        try:
            out = remediation.view(fresh, run, pid, full=True)
        except KeyError as exc:
            raise HTTPException(404, "unknown proposal") from exc
        finally:
            fresh.close()
        out["validating"] = validating.get(f"{run}:{pid}")
        return out

    # approve | reject | validate | export | push. Humans only; agents have no route here.
    @app.post("/api/proposals/{pid}/{decision}")
    def decide_or_validate(pid: str, decision: str, body: Decision | RunRef) -> dict:
        stored_run(body.run)
        if decision == "validate":
            return start_validation(pid, body.run)
        if decision == "push":
            if not push_allowed():  # a setting, not a server fault
                raise HTTPException(403, "pushing is off: see GUARDIAN_ALLOW_PUSH in .env.example")
            confirm = (body.model_extra or {}).get("confirm_repo", "")
            try:
                return push_fix(db, body.run, pid, str(confirm))
            except props.ApprovalError as exc:
                raise HTTPException(409, str(exc)) from exc
            except PushError as exc:
                raise HTTPException(502, str(exc)) from exc
            except KeyError as exc:
                raise HTTPException(404, "unknown proposal") from exc
        if decision == "export":
            try:
                return export_fix(db, body.run, pid)
            except props.ApprovalError as exc:
                raise HTTPException(409, str(exc)) from exc
            except KeyError as exc:
                raise HTTPException(404, "unknown proposal") from exc
        if not isinstance(body, Decision):
            raise HTTPException(422, "approver is required")
        conn = connect(db)
        try:
            record = props.decide(
                conn, body.run, pid, "approved" if decision == "approve" else "rejected",
                body.approver, body.note,
            )  # fmt: skip
        except props.ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (KeyError, ValueError) as exc:
            raise HTTPException(404 if isinstance(exc, KeyError) else 422, str(exc)) from exc
        finally:
            conn.close()
        return record

    # Check the approval gate, then validate on a background thread; poll via the proposal.
    def start_validation(pid: str, run: str) -> dict:
        key = f"{run}:{pid}"
        if (validating.get(key) or {}).get("state") == "running":
            raise HTTPException(409, "validation is already running")
        gate = connect(db)
        try:
            props.require_approved(gate, run, pid)
        except props.ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, "unknown proposal") from exc
        finally:
            gate.close()
        state = {"state": "running", "step": "Starting", "error": None}
        validating[key] = state

        def work() -> None:
            try:
                report = remediation.validate_for_run(
                    db, run, pid, on_step=lambda m: state.update(step=m)
                )
                state.update(state="done", step=f"Verdict: {report['verdict']}")
            except Exception as exc:
                state.update(state="error", error=f"{type(exc).__name__}: {exc}"[:400])

        validator.submit(work)
        return dict(state)

    # The agent timeline for a run, readable while it is still going.
    @app.get("/api/agent-events")
    def agent_events(
        run: str = Query(min_length=1, max_length=200),
        after: int = Query(0, ge=0),
        limit: int = Query(300, ge=1, le=500),
    ) -> dict:
        """The agent timeline for a run directory, readable while the run is still going."""
        fresh = connect_readonly(db)
        try:
            return agent_timeline(fresh, run, after, limit)
        finally:
            fresh.close()

    # A drawable subgraph for the graph tab.
    @app.get("/api/graph-overview")
    def graph_view(
        run: str,
        scope: str = Query("runtime", pattern="^(runtime|all)$"),
        risk: str | None = Query(None, pattern="^(Critical|High|Medium|Low)$"),
        q: str | None = Query(None, max_length=80),
        limit: int = Query(160, ge=20, le=400),
    ) -> dict:
        """A drawable subgraph: direct dependencies and vulnerable packages with their paths."""
        run = known_run(run)
        return graph_overview(
            graph(run), findings_by_label(conn, run), scope=scope, min_risk=risk, q=q, limit=limit
        )

    def sbom_data(run: str) -> dict:
        path = jail(run) / "sbom.cdx.json"
        if not path.exists():
            raise HTTPException(404, "this run has no SBOM")
        stamp = path.stat().st_mtime_ns
        cached = sbom_cache.get(run)
        if cached is None or cached[0] != stamp:
            cached = (stamp, load_sbom(path))
            sbom_cache[run] = cached
        return cached[1]

    # The CycloneDX component list, filtered and paged.
    @app.get("/api/sbom")
    def sbom(
        run: str,
        q: str | None = Query(None, max_length=80),
        type: str | None = Query(None, max_length=30),
        ecosystem: str | None = Query(None, max_length=30),
        vulnerable: bool = False,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ) -> dict:
        """The run's CycloneDX SBOM as a searchable table, joined with finding counts."""
        run = known_run(run)
        return sbom_view(
            sbom_data(run),
            findings_by_label(conn, run),
            q=q,
            type_=type,
            ecosystem=ecosystem,
            vulnerable_only=vulnerable,
            limit=limit,
            offset=offset,
        )

    # The raw CycloneDX JSON file.
    @app.get("/api/sbom/download")
    def sbom_download(run: str) -> FileResponse:
        run = known_run(run)
        path = jail(run) / "sbom.cdx.json"
        if not path.exists():
            raise HTTPException(404, "this run has no SBOM")
        return FileResponse(
            path,
            media_type="application/vnd.cyclonedx+json",
            filename=f"{Path(run).name}.cdx.json",
        )

    # The supervisor's accepted report.
    @app.get("/api/agent-report")
    def agent_report(run: str) -> dict:
        """The accepted agent report (Markdown), or a labelled partial report."""
        run = known_run(run)
        path = jail(run) / "agent-report.md"
        if not path.exists():
            raise HTTPException(404, "this run has no agent report")
        return {"run_id": run, "markdown": path.read_text()}

    # Requirement checklist with evidence for each item.
    @app.get("/api/checklist")
    def checklist(run: str) -> dict:
        return as_dict(evaluate(known_run(run), db))

    if (ui_dir / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=ui_dir / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(ui_dir / "index.html")

    return app
