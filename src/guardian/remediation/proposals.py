"""Proposal, approval and validation storage (schema v4).

The approval gate lives here and nowhere else: ``decide`` is the only way to approve, it needs a
named human approver, and the approval records the SHA-256 of the exact proposal.
``require_approved`` re-checks that hash, so a proposal can only be applied as it was
approved. Agents are never given a tool that calls ``decide``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime

from guardian.remediation.schemas import Proposal, ProposalStatus

log = logging.getLogger("guardian.approval")


class ApprovalError(Exception):
    """A proposal may not be applied: not approved, rejected, or changed since approval."""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# Hash of the proposal's content (not its id): approval is bound to this.
def proposal_sha(p: Proposal) -> str:
    return hashlib.sha256(p.model_copy(update={"id": ""}).model_dump_json().encode()).hexdigest()


def add_proposal(conn: sqlite3.Connection, p: Proposal, created_by: str) -> Proposal:
    """Store a proposal, or return the existing one if an identical one exists for the finding."""
    sha = proposal_sha(p)
    with conn:
        row = conn.execute(
            "SELECT id FROM proposals WHERE run_id = ? AND finding_id = ? AND sha256 = ?",
            (p.run_id, p.finding_id, sha),
        ).fetchone()
        if row:
            return get_proposal(conn, row[0])
        if p.applicable:  # one fix per package change: another finding on it maps to the same one
            key = (p.package, p.current_version, p.action, p.target, p.edits)
            for other in list_proposals(conn, p.run_id):
                if (
                    other.package,
                    other.current_version,
                    other.action,
                    other.target,
                    other.edits,
                ) == key:
                    return other
        n = conn.execute("SELECT COUNT(*) FROM proposals WHERE run_id = ?", (p.run_id,)).fetchone()[
            0
        ]
        stored = p.model_copy(update={"id": f"R-{n + 1:03d}"})
        conn.execute(
            "INSERT INTO proposals(id, run_id, finding_id, sha256, proposal_json, created_by, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f"{p.run_id}:{stored.id}", p.run_id, p.finding_id, sha, stored.model_dump_json(),
             created_by, now()),
        )  # fmt: skip
    return stored


def _key(run_id: str, proposal_id: str) -> str:
    return proposal_id if ":" in proposal_id else f"{run_id}:{proposal_id}"


# Load one stored proposal or raise KeyError.
def get_proposal(conn: sqlite3.Connection, key: str) -> Proposal:
    row = conn.execute("SELECT proposal_json FROM proposals WHERE id = ?", (key,)).fetchone()
    if row is None:
        raise KeyError(f"unknown proposal {key}")
    return Proposal.model_validate_json(row[0])


def list_proposals(conn: sqlite3.Connection, run_id: str) -> list[Proposal]:
    rows = conn.execute(
        "SELECT proposal_json FROM proposals WHERE run_id = ? ORDER BY id", (run_id,)
    )
    return [Proposal.model_validate_json(r[0]) for r in rows]


# The full, ordered approval log for a proposal.
def approvals(conn: sqlite3.Connection, run_id: str, proposal_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT decision, approver, at, note, proposal_sha FROM approvals WHERE proposal_id = ? "
        "ORDER BY seq",
        (_key(run_id, proposal_id),),
    )
    return [
        dict(zip(("decision", "approver", "at", "note", "proposal_sha"), r, strict=True))
        for r in rows
    ]


def decide(
    conn: sqlite3.Connection,
    run_id: str,
    proposal_id: str,
    decision: str,
    approver: str,
    note: str = "",
) -> dict:
    """Record a human decision. The latest decision wins; every one stays in the log."""
    if decision not in {"approved", "rejected"}:
        raise ValueError("decision must be 'approved' or 'rejected'")
    approver = approver.strip()
    if not approver:
        raise ValueError("an approver name is required")
    key = _key(run_id, proposal_id)
    p = get_proposal(conn, key)
    if decision == "approved" and not p.applicable:
        raise ApprovalError(
            "this proposal changes no file (escalation or missing inputs); there is nothing to "
            f"approve for application. Needs: {', '.join(p.needs) or 'a reviewer'}"
        )
    sha = proposal_sha(p)
    with conn:
        conn.execute(
            "INSERT INTO approvals(proposal_id, decision, approver, at, note, proposal_sha) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (key, decision, approver, now(), note[:500], sha),
        )
    log.info("decision %s %s by %s", proposal_id, decision, approver)
    return approvals(conn, run_id, proposal_id)[-1]


def require_approved(conn: sqlite3.Connection, run_id: str, proposal_id: str) -> dict:
    """Return the approval record, or raise ApprovalError saying why not."""
    key = _key(run_id, proposal_id)
    p = get_proposal(conn, key)
    log = approvals(conn, run_id, proposal_id)
    if not log:
        raise ApprovalError(f"proposal {proposal_id} has not been approved by a human")
    last = log[-1]
    if last["decision"] != "approved":
        raise ApprovalError(f"proposal {proposal_id} was rejected by {last['approver']}")
    if last["proposal_sha"] != proposal_sha(p):
        raise ApprovalError("the proposal changed after it was approved; approve it again")
    return last


# Append a validation report; rows are never updated.
def add_validation(conn: sqlite3.Connection, run_id: str, proposal_id: str, report: dict) -> None:
    with conn:
        conn.execute(
            "INSERT INTO validations(proposal_id, verdict, at, report_json) VALUES (?, ?, ?, ?)",
            (_key(run_id, proposal_id), report["verdict"], now(), _dump(report)),
        )


def _dump(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


# All validation reports for a proposal, oldest first.
def validations(conn: sqlite3.Connection, run_id: str, proposal_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT at, report_json FROM validations WHERE proposal_id = ? ORDER BY seq",
        (_key(run_id, proposal_id),),
    )
    return [{**json.loads(r[1]), "at": r[0]} for r in rows]


# Derive the proposal's status from its approvals and validations.
def status(conn: sqlite3.Connection, run_id: str, proposal_id: str) -> ProposalStatus:
    log = approvals(conn, run_id, proposal_id)
    val = validations(conn, run_id, proposal_id)
    if val:
        return ProposalStatus.VALIDATED if val[-1]["verdict"] != "failed" else ProposalStatus.FAILED
    if not log:
        return ProposalStatus.PROPOSED
    return ProposalStatus.APPROVED if log[-1]["decision"] == "approved" else ProposalStatus.REJECTED
