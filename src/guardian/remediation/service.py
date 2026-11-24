"""Shared by the CLI and the API: proposal views and the validate entry point."""

from __future__ import annotations

import sqlite3

from guardian.remediation import proposals as props
from guardian.remediation.proposals import ApprovalError
from guardian.remediation.validate import validate


def view(conn: sqlite3.Connection, run_id: str, proposal_id: str, *, full: bool = False) -> dict:
    p = props.get_proposal(
        conn, f"{run_id}:{proposal_id}" if ":" not in proposal_id else proposal_id
    )
    vals = props.validations(conn, run_id, p.id)
    out = {
        **p.model_dump(mode="json"),
        "status": props.status(conn, run_id, p.id).value,
        "approvals": props.approvals(conn, run_id, p.id),
    }
    if full:
        out["validations"] = vals
    else:
        out["validations"] = [
            {"verdict": v["verdict"], "at": v["at"], "reasons": v.get("reasons", [])} for v in vals
        ]
    return out


def run_target(conn: sqlite3.Connection, run_id: str) -> str:
    row = conn.execute("SELECT target FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown run {run_id}")
    return row[0]


def validate_for_run(db: str, run_id: str, proposal_id: str, on_step=None) -> dict:
    """Validate an approved proposal of a stored run (target and run directory come from the
    store, never from the caller)."""
    from guardian.store import connect

    conn = connect(db)
    try:
        target = run_target(conn, run_id)
    finally:
        conn.close()
    return validate(db, run_id, proposal_id, target, run_id, on_step=on_step)


__all__ = ["ApprovalError", "run_target", "validate_for_run", "view"]
