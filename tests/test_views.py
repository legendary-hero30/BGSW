"""Graph overview, SBOM table and agent timeline views, on real objects and a real ledger."""

import json
import shutil

import pytest

from guardian.agents.ledger import Ledger
from guardian.api.views import (
    agent_timeline,
    findings_by_label,
    graph_overview,
    load_sbom,
    sbom_view,
)
from guardian.schemas import Component, DependencyGraph, DependencyScope, GraphEdge, SbomComponent
from guardian.store import connect, save_run
from guardian.tools.runner import WORKSPACE
from tests.agent_support import sample_findings

DIR = WORKSPACE / "runs" / "pytest-views"


def node(ref, name, version="1.0.0", scope=DependencyScope.RUNTIME, direct=False):
    return SbomComponent(
        bom_ref=ref, component=Component(name=name, version=version), scope=scope, direct=direct
    )


def graph():
    return DependencyGraph(
        root=".",
        nodes=(
            node(".", "app"),
            node("a", "a", direct=True),
            node("b", "b"),
            node("vuln", "vuln"),
            node("dev", "devtool", scope=DependencyScope.DEV, direct=True),
            node("devvuln", "devvuln", scope=DependencyScope.DEV),
        ),
        edges=(
            GraphEdge(source=".", target="a"),
            GraphEdge(source="a", target="b"),
            GraphEdge(source="b", target="vuln"),
            GraphEdge(source=".", target="dev"),
            GraphEdge(source="dev", target="devvuln"),
        ),
    )


BY_LABEL = {"vuln@1.0.0": (4, 2), "devvuln@1.0.0": (3, 1), "b@1.0.0": (1, 1)}


def ids(view):
    return {n["data"]["id"] for n in view["nodes"]}


def test_default_focus_is_direct_dependencies_and_vulnerable_packages_with_their_paths():
    v = graph_overview(graph(), BY_LABEL)
    assert ids(v) == {".", "a", "b", "vuln"}  # runtime only; the dev subtree is left out
    by = {n["data"]["id"]: n["data"] for n in v["nodes"]}
    assert by["vuln"]["risk"] == "Critical" and by["vuln"]["findings"] == 2
    assert by["a"]["role"] == "direct" and by["b"]["role"] == "transitive"
    assert by["."]["role"] == "root" and by["vuln"]["focus"] is True and by["b"]["focus"] is True
    assert {e["data"]["id"] for e in v["edges"]} == {".->a", "a->b", "b->vuln"}
    assert v["stats"]["total_nodes"] == 3 and v["stats"]["truncated"] is False


def test_scope_all_includes_dev_and_risk_floor_narrows():
    assert {"dev", "devvuln"} <= ids(graph_overview(graph(), BY_LABEL, scope="all"))
    high = graph_overview(graph(), BY_LABEL, scope="all", min_risk="High")
    assert ids(high) == {".", "a", "b", "vuln", "dev", "devvuln"}
    critical = graph_overview(graph(), BY_LABEL, scope="all", min_risk="Critical")
    assert ids(critical) == {".", "a", "b", "vuln"}


def test_search_focuses_matching_names():
    v = graph_overview(graph(), BY_LABEL, q="VU")
    assert (
        ids(v) == {".", "a", "b", "vuln"}
        and graph_overview(graph(), BY_LABEL, q="zzz")["stats"]["shown_nodes"] == 0
    )


def test_a_big_graph_is_truncated_honestly():
    nodes = [node(".", "app")] + [node(f"d{i}", f"d{i}", direct=True) for i in range(120)]
    edges = tuple(GraphEdge(source=".", target=f"d{i}") for i in range(120))
    v = graph_overview(DependencyGraph(root=".", nodes=tuple(nodes), edges=edges), {}, limit=30)
    assert v["stats"]["shown_nodes"] <= 29 and v["stats"]["truncated"] is True
    assert v["stats"]["focus_skipped"] >= 90


CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1",
    "version": 1,
    "metadata": {
        "timestamp": "2026-11-23T00:00:00Z",
        "tools": {"components": [{"name": "syft", "version": "1.57.2"}]},
        "component": {"name": "/home/someone/secret/path/myapp"},
    },
    "components": [
        {
            "bom-ref": "1",
            "type": "library",
            "name": "lodash",
            "version": "4.17.15",
            "purl": "pkg:npm/lodash@4.17.15",
            "licenses": [{"license": {"id": "MIT"}}],
            "properties": [
                {"name": "syft:package:foundBy", "value": "javascript-lock-cataloger"},
                {"name": "syft:location:0:path", "value": "/package-lock.json"},
            ],
        },
        {
            "bom-ref": "2",
            "type": "library",
            "name": "ms",
            "version": "2.0.0",
            "purl": "pkg:npm/ms@2.0.0",
        },
        {
            "bom-ref": "3",
            "type": "library",
            "name": "actions/checkout",
            "version": "v2",
            "purl": "pkg:github/actions/checkout@v2",
        },
        {"bom-ref": "4", "type": "file", "name": "/package-lock.json"},
    ],
    "dependencies": [{"ref": "1", "dependsOn": ["2"]}],
}


@pytest.fixture
def sbom(tmp_path):
    shutil.rmtree(DIR, ignore_errors=True)
    DIR.mkdir(parents=True)
    path = DIR / "sbom.cdx.json"
    path.write_text(json.dumps(CDX))
    yield load_sbom(path)
    shutil.rmtree(DIR, ignore_errors=True)


def test_sbom_document_summary_and_no_host_path_leak(sbom):
    d = sbom["document"]
    assert (d["format"], d["spec_version"], d["components"], d["dependency_records"]) == (
        "CycloneDX",
        "1.5",
        4,
        1,
    )
    assert d["subject"] == "myapp" and d["tools"] == ["syft 1.57.2"]
    row = sbom["rows"][0]
    assert row["ecosystem"] == "npm" and row["licenses"] == ["MIT"]
    assert (
        row["found_by"] == "javascript-lock-cataloger" and row["location"] == "/package-lock.json"
    )


def test_sbom_view_joins_findings_filters_sorts_and_pages(sbom):
    v = sbom_view(sbom, {"lodash@4.17.15": (4, 2), "ms@2.0.0": (1, 1)})
    assert [i["label"] for i in v["items"]][:2] == ["lodash@4.17.15", "ms@2.0.0"]  # by risk
    assert v["items"][0]["risk"] == "Critical" and v["items"][0]["findings"] == 2
    assert v["summary"]["by_type"] == {"library": 3, "file": 1}
    assert v["summary"]["by_ecosystem"] == {"npm": 2, "github": 1, "none": 1}
    assert v["summary"]["with_findings"] == 2
    assert v["summary"]["top_licenses"]["MIT"] == 1
    assert sbom_view(sbom, {}, q="check")["total"] == 1
    assert sbom_view(sbom, {}, type_="file")["total"] == 1
    assert sbom_view(sbom, {}, ecosystem="github")["items"][0]["name"] == "actions/checkout"
    assert sbom_view(sbom, {"ms@2.0.0": (1, 1)}, vulnerable_only=True)["total"] == 1
    page = sbom_view(sbom, {}, limit=2, offset=3)
    assert page["total"] == 4 and len(page["items"]) == 1
    assert "_rank" not in page["items"][0]


def test_findings_by_label_takes_the_highest_risk_and_counts_all():
    shutil.rmtree(DIR, ignore_errors=True)
    DIR.mkdir(parents=True)
    fs, g = sample_findings()
    conn = connect("runs/pytest-views/guardian.db")
    save_run(
        conn,
        "runs/x",
        {"target": {"name": "t", "commit": "c" * 40}, "generated_at": "2026-11-23T00:00:00"},
        fs,
        g,
    )
    labels = findings_by_label(conn, "runs/x")
    assert set(labels) == {"lodash@4.17.15", "ms@2.0.0", "node@12-alpine"}
    assert labels["lodash@4.17.15"][1] == 1 and labels["lodash@4.17.15"][0] >= 1
    conn.close()
    shutil.rmtree(DIR, ignore_errors=True)


@pytest.fixture
def timeline():
    shutil.rmtree(DIR, ignore_errors=True)
    led = Ledger("runs/pytest-views/guardian.db")
    led.start_run(
        goal="assess",
        target="t",
        provider="deepinfra",
        model="m",
        budget={"max_steps": 100},
        prompts={},
    )
    led.set_stored_run("runs/live")
    led.log("supervisor", "model_call", None, {"step": 1})
    led.log(
        "supervisor",
        "model_response",
        None,
        {"text": "planning", "tokens_in": 100, "tokens_out": 20},
    )
    led.log("risk", "tool_call", "get_finding", {"args": {}, "preview": "x"})
    led.log("supervisor", "delegate", "task", {"result_text": "the answer"})
    led.log("risk", "tool_error", "x", {"error": True})
    led.plan_upsert("supervisor", None, goal="scan", rationale="why")
    led.hypothesis_add("risk", "a claim long enough to count", "risk", ["E-001"], ["F-001"], "low")
    yield led, connect("runs/pytest-views/guardian.db")
    led.close()
    shutil.rmtree(DIR, ignore_errors=True)


def test_timeline_of_a_live_run_aggregates_usage_and_supports_polling(timeline):
    _led, conn = timeline
    t = agent_timeline(conn, "runs/live")
    info = t["agent_run"]
    assert info["status"] == "running" and t["live"] is True
    assert info["live_usage"] == {"steps": 1, "tool_calls": 3, "tokens": 120}
    assert info["budget"] == {"max_steps": 100} and info["usage"] is None
    assert [e["kind"] for e in t["events"]][:3] == ["model_call", "model_response", "tool_call"]
    assert t["plan"][0]["id"] == "P-01" and t["hypotheses"][0]["status"] == "proposed"
    after = agent_timeline(conn, "runs/live", after=t["last_seq"] - 1)
    assert [e["seq"] for e in after["events"]] == [t["last_seq"]]
    assert agent_timeline(conn, "runs/live", limit=2)["events"][-1]["seq"] == 2


def test_timeline_of_a_finished_run_carries_final_usage_and_report_flag(timeline):
    led, conn = timeline
    led.finish_run("completed", None, {"steps": 9}, "# Report")
    t = agent_timeline(conn, "runs/live")
    assert t["live"] is False and t["agent_run"]["usage"] == {"steps": 9}
    assert t["agent_run"]["has_report"] is True


def test_timeline_for_an_unknown_run_is_empty(timeline):
    _, conn = timeline
    assert agent_timeline(conn, "runs/none") == {
        "agent_run": None,
        "events": [],
        "plan": [],
        "hypotheses": [],
        "last_seq": 0,
    }


def test_running_run_with_no_recent_events_is_shown_as_interrupted():
    from datetime import UTC, datetime, timedelta

    from guardian.api.views import agent_timeline
    from guardian.store import connect

    conn = connect("runs/pytest-views-stall/g.db")
    old = (datetime.now(UTC) - timedelta(minutes=30)).isoformat(timespec="milliseconds")
    with conn:
        conn.execute(
            "INSERT INTO agent_runs(agent_run_id, run_id, goal, target, provider, model, status, "
            "budget_json, prompts_json, started_at) VALUES ('s1','r','g','t','p','m','running',"
            "'{}','{}',?)",
            (old,),
        )
        conn.execute(
            "INSERT INTO agent_events(agent_run_id, seq, ts, agent, kind, name, payload_json) "
            "VALUES ('s1', 1, ?, 'runner', 'note', NULL, '{}')",
            (old,),
        )
    out = agent_timeline(conn, "r")
    assert out["agent_run"]["status"] == "interrupted" and out["live"] is False
    assert "no activity" in out["agent_run"]["stop_reason"]
    conn.close()
    shutil.rmtree(WORKSPACE / "runs/pytest-views-stall", ignore_errors=True)
