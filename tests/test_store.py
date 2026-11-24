"""SQLite evidence store: exact round trip, atomic replace, constraints, path jail."""

import shutil
import sqlite3

import pytest

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
from guardian.store import connect, load_findings, save_run, top_findings
from guardian.tools.runner import WORKSPACE, PathJailError

DB_DIR = WORKSPACE / "runs" / "pytest-store"
DB = "runs/pytest-store/test.db"


@pytest.fixture
def conn():
    shutil.rmtree(DB_DIR, ignore_errors=True)
    c = connect(DB)
    yield c
    c.close()
    shutil.rmtree(DB_DIR, ignore_errors=True)


def sample(n=3):
    evidence = tuple(EvidenceRecord(id=f"E-{i:03d}", kind=EvidenceKind.ADVISORY, tool="t",
                                    ref=f"GHSA-{i}") for i in range(1, n + 1))  # fmt: skip
    findings = []
    for i in range(1, n + 1):
        factors = RiskFactors(cvss=10.0 - i)
        findings.append(Finding(
            id=f"F-{i:03d}", type=FindingType.VULNERABLE_TRANSITIVE, title=f"pkg{i}: vuln",
            component=Component(name=f"pkg{i}", version="1.0.0", purl=f"pkg:npm/pkg{i}@1.0.0"),
            dependency_path=("app@1.0.0", "mid@1.0.0", f"pkg{i}@1.0.0"),
            evidence=(EvidenceRef(evidence_id=f"E-{i:03d}", tool="t", ref=f"GHSA-{i}"),),
            factors=factors, risk=score_risk(factors),
        ))  # fmt: skip
    graph = DependencyGraph(
        root=".", nodes=(SbomComponent(bom_ref=".", component=Component(name="app")),
                         SbomComponent(bom_ref="node_modules/mid",
                                       component=Component(name="mid", version="1.0.0"))),
        edges=(GraphEdge(source=".", target="node_modules/mid"),),
    )  # fmt: skip
    summary = {"target": {"name": "t", "commit": "c" * 40}, "generated_at": "2026-11-23T00:00:00"}
    return FindingSet(evidence=evidence, findings=tuple(findings)), graph, summary


def test_round_trip_is_exact(conn):
    fs, graph, summary = sample()
    save_run(conn, "runs/x", summary, fs, graph)
    assert load_findings(conn, "runs/x") == fs
    assert conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0] == 1
    links = conn.execute("SELECT COUNT(*) FROM finding_evidence").fetchone()[0]
    assert links == sum(len(f.evidence) for f in fs.findings)


def test_resave_replaces_run_atomically(conn):
    fs, graph, summary = sample(3)
    save_run(conn, "runs/x", summary, fs, graph)
    fs2, _, _ = sample(2)
    save_run(conn, "runs/x", summary, fs2, graph)
    assert load_findings(conn, "runs/x") == fs2
    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


def test_failed_save_leaves_previous_run(conn):
    fs, graph, summary = sample(2)
    save_run(conn, "runs/x", summary, fs, graph)
    with pytest.raises(KeyError):
        save_run(conn, "runs/x", {"generated_at": "x"}, fs, graph)  # no 'target': fails mid-way
    assert load_findings(conn, "runs/x") == fs


def test_top_findings_keep_rank_order(conn):
    fs, graph, summary = sample(3)
    save_run(conn, "runs/x", summary, fs, graph)
    assert [r[0] for r in top_findings(conn, "runs/x", 2)] == ["F-001", "F-002"]


def test_foreign_keys_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO evidence VALUES ('nope', 'E-1', 'k', 't', NULL, NULL, NULL, "
                     "NULL, NULL, NULL, '{}')")  # fmt: skip


def test_unknown_run_raises(conn):
    with pytest.raises(KeyError):
        load_findings(conn, "runs/missing")


def test_db_path_is_jailed():
    with pytest.raises(PathJailError):
        connect("../outside.db")


def test_schema_version_mismatch(conn):
    conn.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    conn.commit()
    with pytest.raises(RuntimeError, match="schema"):
        connect(DB)


def test_an_open_connection_does_not_hold_the_write_lock():
    """Regression: connect() left an implicit transaction open, so a second connection's write
    blocked for the whole 30 s timeout (found by the agent ledger running alongside a tool)."""
    import time

    shutil.rmtree(DB_DIR, ignore_errors=True)
    first = connect(DB)
    second = connect(DB)
    started = time.monotonic()
    with second:
        second.execute("INSERT INTO meta(key, value) VALUES ('probe', '1')")
    assert time.monotonic() - started < 2
    assert first.execute("SELECT value FROM meta WHERE key = 'probe'").fetchone() == ("1",)
    first.close()
    second.close()
    shutil.rmtree(DB_DIR, ignore_errors=True)
