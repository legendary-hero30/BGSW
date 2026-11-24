"""Approval gate: named approver, bound to the exact proposal, append-only."""

import sqlite3

import pytest

from guardian.remediation.engine import propose
from guardian.remediation.proposals import (
    ApprovalError,
    add_proposal,
    add_validation,
    approvals,
    decide,
    require_approved,
    status,
    validations,
)
from guardian.remediation.schemas import ProposalStatus
from guardian.store import connect
from tests.agent_support import sample_findings

MANIFEST = {"dependencies": {"lodash": "^4.17.0"}}


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr("guardian.store.jail", lambda p: tmp_path / "g.db")
    c = connect("x.db")
    yield c
    c.close()


def make(conn, fid="F-001"):
    fs, _ = sample_findings()
    return add_proposal(conn, propose(fs, fid, MANIFEST, run_id="run1"), "test")


def test_add_is_idempotent_and_ids_are_sequential(conn):
    a, b = make(conn), make(conn)
    assert a.id == b.id == "R-001"
    assert make(conn, "F-002").id == "R-002"


def test_unapproved_cannot_be_applied(conn):
    p = make(conn)
    assert status(conn, "run1", p.id) is ProposalStatus.PROPOSED
    with pytest.raises(ApprovalError, match="not been approved"):
        require_approved(conn, "run1", p.id)


def test_approval_needs_a_named_human_and_is_logged(conn):
    p = make(conn)
    with pytest.raises(ValueError, match="approver"):
        decide(conn, "run1", p.id, "approved", "  ")
    rec = decide(conn, "run1", p.id, "approved", "alice", "ok")
    assert rec["approver"] == "alice" and rec["at"] and rec["proposal_sha"]
    assert require_approved(conn, "run1", p.id)["approver"] == "alice"
    assert status(conn, "run1", p.id) is ProposalStatus.APPROVED


def test_latest_decision_wins_and_history_stays(conn):
    p = make(conn)
    decide(conn, "run1", p.id, "approved", "alice")
    decide(conn, "run1", p.id, "rejected", "bob")
    assert len(approvals(conn, "run1", p.id)) == 2
    with pytest.raises(ApprovalError, match="rejected"):
        require_approved(conn, "run1", p.id)


def test_non_applicable_proposal_cannot_be_approved(conn):
    p = make(conn, "F-002")
    with pytest.raises(ApprovalError, match="nothing to approve"):
        decide(conn, "run1", p.id, "approved", "alice")


def test_tables_are_append_only(conn):
    p = make(conn)
    decide(conn, "run1", p.id, "approved", "alice")
    add_validation(conn, "run1", p.id, {"verdict": "partially_verified"})
    for sql in (
        "UPDATE proposals SET finding_id = 'x'",
        "DELETE FROM proposals",
        "UPDATE approvals SET approver = 'eve'",
        "DELETE FROM approvals",
        "DELETE FROM validations",
    ):
        with pytest.raises(sqlite3.DatabaseError, match=r"append-only|immutable"):
            conn.execute(sql)
    assert validations(conn, "run1", p.id)[0]["verdict"] == "partially_verified"
