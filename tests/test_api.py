"""API: endpoints, filters, graph elements, agent steps, the repo-input job and security."""

import json
import shutil
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from guardian.api.__main__ import main as api_main
from guardian.api.app import create_app
from guardian.schemas import (
    Component,
    DependencyGraph,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRef,
    Finding,
    FindingSet,
    FindingType,
    GraphEdge,
    RiskFactors,
    SbomComponent,
)
from guardian.scoring import score_risk
from guardian.store import connect, save_explanation, save_run
from guardian.tools.runner import WORKSPACE

DIR = WORKSPACE / "runs" / "pytest-api"
DB = "runs/pytest-api/guardian.db"
RUN = "runs/pytest-api/run"


def sample():
    evidence = (
        EvidenceRecord(
            id="E-001",
            kind=EvidenceKind.SCANNER_RESULT,
            tool="grype",
            ref="GHSA-aaaa-bbbb-cccc",
            excerpt="<script>alert(1)</script>",
        ),
        EvidenceRecord(
            id="E-002",
            kind=EvidenceKind.GRAPH_NODE,
            tool="dependency-graph",
            graph_node="node_modules/b",
        ),
        EvidenceRecord(
            id="E-003", kind=EvidenceKind.SCANNER_RESULT, tool="trivy", ref="CVE-2020-1"
        ),
    )
    hi, lo = RiskFactors(cvss=9.0), RiskFactors(cvss=3.0)
    findings = (
        Finding(
            id="F-001",
            type=FindingType.VULNERABLE_TRANSITIVE,
            title="b@1.0.0: proto_%",
            component=Component(name="b", version="1.0.0"),
            dependency_path=("app@1.0.0", "a@1.0.0", "b@1.0.0"),
            introduced_by=("a@1.0.0",),
            advisory_ids=("GHSA-aaaa-bbbb-cccc",),
            evidence=(
                EvidenceRef(evidence_id="E-001", tool="grype"),
                EvidenceRef(evidence_id="E-002", tool="dependency-graph"),
            ),
            factors=hi,
            risk=score_risk(hi),
        ),
        Finding(
            id="F-002",
            type=FindingType.VULNERABLE_IMAGE_PACKAGE,
            title="zlib@1.2: bug",
            component=Component(name="zlib", version="1.2"),
            dependency_path=("node:20@sha256:" + "a" * 64, "zlib@1.2"),
            advisory_ids=("CVE-2020-1",),
            evidence=(EvidenceRef(evidence_id="E-003", tool="trivy"),),
            factors=lo,
            risk=score_risk(lo),
        ),
    )
    graph = DependencyGraph(
        root=".",
        nodes=tuple(
            SbomComponent(bom_ref=r, component=Component(name=n, version=v))
            for r, n, v in (
                (".", "app", "1.0.0"),
                ("node_modules/a", "a", "1.0.0"),
                ("node_modules/b", "b", "1.0.0"),
                ("node_modules/c", "c", "1.0.0"),
            )
        ),
        edges=(
            GraphEdge(source=".", target="node_modules/a"),
            GraphEdge(source=".", target="node_modules/c"),
            GraphEdge(source="node_modules/a", target="node_modules/b"),
            GraphEdge(source="node_modules/c", target="node_modules/b"),
        ),
    )
    return FindingSet(evidence=evidence, findings=findings), graph


def fake_job_runner(job, repo, db):
    job.update(
        status="done",
        step="Complete",
        run_id=RUN,
        findings=2,
        accepted=1,
        rejected=0,
        blocked=0,
        steps=[
            {
                "n": 1,
                "agent": "orchestrator",
                "subagent": "analysis",
                "tool": "task",
                "args": {"subagent_type": "analysis"},
                "result_chars": 10,
            }
        ],
        finished="2026-11-23T00:00:00+00:00",
    )


@pytest.fixture(scope="module")
def client():
    shutil.rmtree(DIR, ignore_errors=True)
    DIR.mkdir(parents=True)
    ui = DIR / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><div id=root></div>")
    (ui / "assets" / "app.js").write_text("console.log(1)")
    (DIR / "run").mkdir(parents=True, exist_ok=True)
    (DIR / "run" / "agent-run.json").write_text(
        json.dumps(
            {
                "provider": "deepinfra",
                "model": "test-model",
                "status": "completed",
                "stop_reason": None,
                "goal": "assess",
                "plan": [{"id": "P-01", "goal": "scan", "status": "done"}],
                "hypotheses": [{"id": "H-01", "status": "verified", "claim": "c"}],
                "usage": {"steps": 4, "tool_calls": 4},
                "tool_calls": [
                    {
                        "agent": "supervisor",
                        "tool": "task",
                        "args": {"subagent_type": "risk"},
                        "result_chars": 10,
                    },
                    {
                        "agent": "risk",
                        "tool": "list_findings",
                        "args": {"limit": 10},
                        "result_chars": 20,
                    },
                    {
                        "agent": "risk",
                        "tool": "get_finding",
                        "args": {"finding_id": "F-001"},
                        "result_chars": 30,
                        "error": True,
                    },
                    {
                        "agent": "risk",
                        "tool": "submit_explanations",
                        "args": {"count": 1},
                        "result_chars": 40,
                    },
                ],
                "blocked_tool_calls": [],
                "final_message": "done",
            }
        )
    )
    (DIR / "run" / "agent-report.md").write_text("# Report\n\nFinding F-001 matters.\n")
    (DIR / "run" / "explanations.json").write_text(
        json.dumps(
            {
                "provider": "deepinfra",
                "model": "test-model",
                "accepted": [{"finding_id": "F-001"}],
                "rejected": [],
                "blocked_tool_calls": [],
                "final_message": "done",
            }
        )
    )
    fs, graph = sample()
    conn = connect(DB)
    save_run(
        conn,
        RUN,
        {
            "target": {"name": "t", "commit": "c" * 40},
            "generated_at": "2026-11-23T00:00:00",
            "findings": 2,
        },
        fs,
        graph,
    )
    save_explanation(conn, RUN, "F-001", "rejected", "deepinfra", "test-model", {"x": 1}, ["bad"])
    save_explanation(conn, RUN, "F-001", "accepted", "deepinfra", "test-model",
                     {"why_it_matters": "w"}, [])  # fmt: skip
    conn.close()
    yield TestClient(create_app(DB, ui, job_runner=fake_job_runner))
    shutil.rmtree(DIR, ignore_errors=True)


def test_runs_and_summary(client):
    runs = client.get("/api/runs").json()
    assert [r["run_id"] for r in runs] == [RUN]
    assert client.get("/api/summary", params={"run": RUN}).json()["findings"] == 2


def test_findings_list_filters_and_search_escaping(client):
    j = client.get("/api/findings", params={"run": RUN}).json()
    assert j["total"] == 2 and [x["id"] for x in j["items"]] == ["F-001", "F-002"]
    assert j["items"][0]["explained"] is True and j["items"][1]["explained"] is False
    typed = client.get("/api/findings", params={"run": RUN, "type": "vulnerable_image_package"})
    assert [x["id"] for x in typed.json()["items"]] == ["F-002"]
    level = j["items"][1]["risk_level"]
    assert client.get("/api/findings", params={"run": RUN, "level": level}).json()["total"] >= 1
    assert (
        client.get("/api/findings", params={"run": RUN, "q": "%"}).json()["total"] == 1
    )  # literal %
    assert client.get("/api/findings", params={"run": RUN, "q": "_"}).json()["total"] == 1
    assert client.get("/api/findings", params={"run": RUN, "q": "zlib"}).json()["total"] == 1
    assert client.get("/api/findings", params={"run": RUN, "limit": 0}).status_code == 422


def test_finding_detail_returns_ordered_evidence_and_explanation(client):
    d = client.get("/api/findings/F-001", params={"run": RUN}).json()
    assert [e["id"] for e in d["evidence"]] == ["E-001", "E-002"]
    assert d["evidence"][0]["excerpt"] == "<script>alert(1)</script>"  # data, escaped by the UI
    assert d["explanation"]["generator"] == "language model"
    assert d["rejected_explanations"] == 1


def test_agent_steps_are_exposed_for_the_view(client):
    j = client.get("/api/agent-steps", params={"run": RUN}).json()
    assert j["provider"] == "deepinfra" and j["generator"] == "language model"
    assert j["status"] == "completed" and j["goal"] == "assess"
    assert [s["tool"] for s in j["steps"]] == [
        "task",
        "list_findings",
        "get_finding",
        "submit_explanations",
    ]
    assert [s["agent"] for s in j["steps"]] == ["supervisor", "risk", "risk", "risk"]
    assert j["steps"][0]["subagent"] == "risk" and j["steps"][2]["error"] is True
    assert j["counts"] == {
        "tool_calls": 4,
        "hypotheses": 1,
        "verified": 1,
        "blocked": 0,
        "accepted": 1,
        "rejected": 0,
    }
    assert j["plan"][0]["id"] == "P-01" and j["hypotheses"][0]["status"] == "verified"
    assert j["final_message"] == "done"


def test_agent_report_is_served_or_404(client):
    r = client.get("/api/agent-report", params={"run": RUN}).json()
    assert r["markdown"].startswith("# Report")
    assert client.get("/api/agent-report", params={"run": "../../etc"}).status_code == 404


def test_graph_from_dependency_graph(client):
    g = client.get("/api/graph/F-001", params={"run": RUN}).json()
    roles = {n["data"]["id"]: n["data"]["role"] for n in g["nodes"]}
    assert roles == {
        ".": "root",
        "node_modules/a": "path",
        "node_modules/b": "target",
        "node_modules/c": "context",
    }
    on_path = {e["data"]["id"] for e in g["edges"] if e["data"]["on_path"]}
    assert on_path == {".->node_modules/a", "node_modules/a->node_modules/b"}
    assert "node_modules/c->node_modules/b" in {e["data"]["id"] for e in g["edges"]}


def test_graph_from_recorded_image_path(client):
    g = client.get("/api/graph/F-002", params={"run": RUN}).json()
    assert g["source"] == "recorded path"
    assert [n["data"]["role"] for n in g["nodes"]] == ["root", "target"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/findings",
        "/api/summary",
        "/api/checklist",
        "/api/findings/F-001",
        "/api/graph/F-001",
        "/api/agent-steps",
        "/api/agent-report",
    ],
)
def test_unknown_run_is_404(client, path):
    assert client.get(path, params={"run": "../../etc"}).status_code == 404


def test_unknown_finding_is_404(client):
    assert client.get("/api/findings/F-999", params={"run": RUN}).status_code == 404


@pytest.mark.parametrize("method", ["put", "delete", "patch"])
def test_only_the_controlled_post_is_allowed(client, method):
    assert getattr(client, method)("/api/runs").status_code == 405
    assert client.post("/api/summary").status_code == 405


def test_start_run_validates_and_queues_a_job(client):
    assert client.post("/api/runs", json={"repo": "http://github.com/a/b"}).status_code == 400
    assert client.post("/api/runs", json={"repo": "https://gitlab.com/a/b"}).status_code == 400
    assert client.post("/api/runs", json={}).status_code == 422
    started = client.post("/api/runs", json={"repo": "https://github.com/OWASP/NodeGoat"})
    assert started.status_code == 202
    job = started.json()
    assert job["status"] == "queued" and job["repo"] == "https://github.com/OWASP/NodeGoat"
    for _ in range(100):
        current = client.get(f"/api/jobs/{job['id']}").json()
        if current["status"] in {"done", "error"}:
            break
        time.sleep(0.02)
    assert current["status"] == "done" and current["run_id"] == RUN
    assert current["findings"] == 2 and current["accepted"] == 1
    assert client.get("/api/jobs/does-not-exist").status_code == 404


def test_security_headers_and_ui(client):
    r = client.get("/")
    assert r.status_code == 200 and "id=root" in r.text
    csp = r.headers["content-security-policy"]
    assert (
        "script-src 'self'" in csp
        and "object-src 'none'" in csp
        and "frame-ancestors 'none'" in csp
    )
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../../guardian.db").status_code == 404
    assert "access-control-allow-origin" not in client.get("/api/runs").headers


def test_store_connection_is_read_only(client):
    from guardian.store import connect_readonly

    conn = connect_readonly(DB)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM runs")
    conn.close()


def test_cli_refuses_non_loopback_host(capsys):
    assert api_main(["--host", "0.0.0.0"]) == 2  # noqa: S104 - asserting it is refused
    assert "loopback" in capsys.readouterr().err
