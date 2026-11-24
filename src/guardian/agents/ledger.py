"""Shared agent memory and audit trail, stored in the evidence database (schema v3).

* ``agent_events``: append-only log of every model call, tool call, delegation, plan revision,
  hypothesis and decision. The database refuses UPDATE and DELETE on it.
* ``plan_items``: the supervisor's living plan (AGENTS.md section 5 plan item). Every change is
  also appended to the event log, so plan revisions can be replayed.
* ``hypotheses``: LLM inferences, kept apart from tool facts, each citing evidence.

Everything persisted is passed through ``redact_obj`` first.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from guardian.redact import redact, redact_obj
from guardian.store import DEFAULT_DB, connect

PLAN_STATUSES = ("pending", "in_progress", "done", "blocked", "dropped")
HYPOTHESIS_STATUSES = ("proposed", "verified", "rejected", "needs_more_evidence")
MAX_PAYLOAD_CHARS = 6000


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _clip(value, limit: int = MAX_PAYLOAD_CHARS):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"…[+{len(value) - limit} chars]"
    return value


class Ledger:
    def __init__(self, db: str | Path = DEFAULT_DB, agent_run_id: str | None = None) -> None:
        self.db = db
        self.agent_run_id = agent_run_id or uuid4().hex[:12]
        self._lock = (
            threading.RLock()
        )  # reentrant: id allocation and insert are one critical section
        self._conn: sqlite3.Connection = connect(db, shared=True)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- run lifecycle ----------------------------------------------------------------------------
    def start_run(
        self, *, goal: str, target: str, provider: str, model: str, budget: dict, prompts: dict
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO agent_runs(agent_run_id, goal, target, provider, model, status, "
                "budget_json, prompts_json, started_at) VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)",
                (
                    self.agent_run_id,
                    redact(goal),
                    target,
                    provider,
                    model,
                    json.dumps(budget),
                    json.dumps(prompts),
                    _now(),
                ),
            )

    def reap_stale(self, max_age_s: int = 3600) -> int:
        """Mark runs still 'running' after ``max_age_s`` as interrupted (a killed process cannot
        close its own record). Returns how many were marked."""
        cutoff = datetime.fromtimestamp(datetime.now(UTC).timestamp() - max_age_s, UTC)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE agent_runs SET status = 'interrupted', finished_at = ?, "
                "stop_reason = 'the process ended without closing this run' "
                "WHERE status = 'running' AND agent_run_id != ? AND started_at < ?",
                (_now(), self.agent_run_id, cutoff.isoformat(timespec="milliseconds")),
            )
        return cur.rowcount

    def set_stored_run(self, run_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE agent_runs SET run_id = ? WHERE agent_run_id = ?",
                (run_id, self.agent_run_id),
            )

    def finish_run(
        self, status: str, stop_reason: str | None, usage: dict, report_md: str | None
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE agent_runs SET status = ?, stop_reason = ?, usage_json = ?, "
                "report_md = COALESCE(?, report_md), finished_at = ? WHERE agent_run_id = ?",
                (status, stop_reason, json.dumps(usage), report_md, _now(), self.agent_run_id),
            )

    def save_report(self, markdown: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE agent_runs SET report_md = ? WHERE agent_run_id = ?",
                (markdown, self.agent_run_id),
            )

    def run_info(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT goal, target, provider, model, status, stop_reason, run_id, report_md, "
                "budget_json, usage_json, started_at, finished_at FROM agent_runs "
                "WHERE agent_run_id = ?",
                (self.agent_run_id,),
            ).fetchone()
        keys = (
            "goal",
            "target",
            "provider",
            "model",
            "status",
            "stop_reason",
            "run_id",
            "report_md",
            "budget",
            "usage",
            "started_at",
            "finished_at",
        )
        info = dict(zip(keys, row, strict=True))
        info["budget"] = json.loads(info["budget"])
        info["usage"] = json.loads(info["usage"]) if info["usage"] else None
        return info

    # -- events ---------------------------------------------------------------------------------
    def log(
        self, agent: str, kind: str, name: str | None = None, payload: dict | None = None
    ) -> int:
        body = json.dumps(redact_obj(_clip_payload(payload or {})), default=str)
        with self._lock, self._conn:
            seq = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_events WHERE agent_run_id = ?",
                (self.agent_run_id,),
            ).fetchone()[0]
            self._conn.execute(
                "INSERT INTO agent_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.agent_run_id, seq, _now(), agent, kind, name, body),
            )
        return seq

    def events(self, kinds: tuple[str, ...] | None = None, after: int = 0) -> list[dict]:
        sql = (
            "SELECT seq, ts, agent, kind, name, payload_json FROM agent_events "
            "WHERE agent_run_id = ? AND seq > ?"
        )
        args: list = [self.agent_run_id, after]
        if kinds:
            sql += f" AND kind IN ({', '.join('?' * len(kinds))})"
            args += list(kinds)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY seq", args).fetchall()
        return [
            {
                "seq": r[0],
                "ts": r[1],
                "agent": r[2],
                "kind": r[3],
                "name": r[4],
                "payload": json.loads(r[5]),
            }
            for r in rows
        ]

    def count_events(self, kind: str, name: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM agent_events WHERE agent_run_id = ? AND kind = ?"
        args: list = [self.agent_run_id, kind]
        if name is not None:
            sql += " AND name = ?"
            args.append(name)
        with self._lock:
            return self._conn.execute(sql, args).fetchone()[0]

    def invalidate_hypotheses(self, agent: str, reason: str) -> list[str]:
        """Findings were rebuilt and their ids changed: earlier hypotheses no longer hold."""
        stale = [h["id"] for h in self.hypotheses() if h["status"] in {"proposed", "verified"}]
        for hid in stale:
            self.hypothesis_set_status(agent, hid, "needs_more_evidence", [reason])
        return stale

    # -- plan ---------------------------------------------------------------------------------
    def plan_upsert(
        self,
        agent: str,
        item_id: str | None,
        *,
        goal: str | None = None,
        status: str | None = None,
        assigned_agent: str | None = None,
        depends_on: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        rationale: str | None = None,
    ) -> dict:
        """Create or revise a plan item. Returns the item. Raises ValueError on bad input."""
        with self._lock:
            if status is not None and status not in PLAN_STATUSES:
                raise ValueError(f"status must be one of {PLAN_STATUSES}")
            with self._lock:
                existing = (
                    self._conn.execute(
                        "SELECT goal, status, assigned_agent, depends_on_json, evidence_refs_json, "
                        "rationale FROM plan_items WHERE agent_run_id = ? AND id = ?",
                        (self.agent_run_id, item_id),
                    ).fetchone()
                    if item_id
                    else None
                )
                ids = {
                    r[0]
                    for r in self._conn.execute(
                        "SELECT id FROM plan_items WHERE agent_run_id = ?", (self.agent_run_id,)
                    )
                }
            if item_id and existing is None:
                raise ValueError(f"unknown plan item {item_id}")
            for dep in depends_on or []:
                if dep not in ids:
                    raise ValueError(f"depends_on references unknown plan item {dep}")
            if existing is None:
                if not goal or not rationale:
                    raise ValueError("a new plan item needs a goal and a rationale")
                item_id = f"P-{len(ids) + 1:02d}"
                item = {
                    "id": item_id,
                    "goal": redact(goal),
                    "status": status or "pending",
                    "assigned_agent": assigned_agent or "supervisor",
                    "depends_on": depends_on or [],
                    "evidence_refs": evidence_refs or [],
                    "rationale": redact(rationale),
                }
                op = "add"
            else:
                old = dict(
                    zip(
                        (
                            "goal",
                            "status",
                            "assigned_agent",
                            "depends_on",
                            "evidence_refs",
                            "rationale",
                        ),
                        existing,
                        strict=True,
                    )
                )
                item = {
                    "id": item_id,
                    "goal": redact(goal) if goal else old["goal"],
                    "status": status or old["status"],
                    "assigned_agent": assigned_agent or old["assigned_agent"],
                    "depends_on": depends_on
                    if depends_on is not None
                    else json.loads(old["depends_on"]),
                    "evidence_refs": (
                        evidence_refs
                        if evidence_refs is not None
                        else json.loads(old["evidence_refs"])
                    ),
                    "rationale": redact(rationale) if rationale else old["rationale"],
                }
                op = "revise"
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO plan_items VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        self.agent_run_id,
                        item["id"],
                        item["goal"],
                        item["status"],
                        item["assigned_agent"],
                        json.dumps(item["depends_on"]),
                        json.dumps(item["evidence_refs"]),
                        item["rationale"],
                    ),
                )
        self.log(agent, "plan", op, item)
        return item

    def plan(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, goal, status, assigned_agent, depends_on_json, evidence_refs_json, "
                "rationale FROM plan_items WHERE agent_run_id = ? ORDER BY id",
                (self.agent_run_id,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "goal": r[1],
                "status": r[2],
                "assigned_agent": r[3],
                "depends_on": json.loads(r[4]),
                "evidence_refs": json.loads(r[5]),
                "rationale": r[6],
            }
            for r in rows
        ]

    # -- hypotheses -----------------------------------------------------------------------------
    def hypothesis_add(
        self,
        author: str,
        claim: str,
        kind: str,
        evidence: list[str],
        findings: list[str],
        confidence: str,
    ) -> dict:
        with self._lock:
            n = self._conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE agent_run_id = ?", (self.agent_run_id,)
            ).fetchone()[0]
            return self._hypothesis_insert(n, author, claim, kind, evidence, findings, confidence)

    def _hypothesis_insert(
        self, n: int, author: str, claim: str, kind: str, evidence: list[str],
        findings: list[str], confidence: str,
    ) -> dict:  # fmt: skip
        item = {
            "id": f"H-{n + 1:02d}",
            "author": author,
            "claim": redact(claim),
            "kind": kind,
            "evidence_refs": evidence,
            "finding_ids": findings,
            "confidence": confidence,
            "status": "proposed",
            "reasons": [],
        }
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO hypotheses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.agent_run_id,
                    item["id"],
                    author,
                    item["claim"],
                    kind,
                    json.dumps(evidence),
                    json.dumps(findings),
                    confidence,
                    "proposed",
                    "[]",
                    _now(),
                ),
            )
        self.log(author, "hypothesis", "add", item)
        return item

    def hypothesis_set_status(self, agent: str, hid: str, status: str, reasons: list[str]) -> dict:
        if status not in HYPOTHESIS_STATUSES:
            raise ValueError(f"status must be one of {HYPOTHESIS_STATUSES}")
        reasons = [redact(r) for r in reasons]
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE hypotheses SET status = ?, reasons_json = ? "
                "WHERE agent_run_id = ? AND id = ?",
                (status, json.dumps(reasons), self.agent_run_id, hid),
            )
            if cur.rowcount != 1:
                raise ValueError(f"unknown hypothesis {hid}")
        self.log(agent, "hypothesis", "verdict", {"id": hid, "status": status, "reasons": reasons})
        return {"id": hid, "status": status, "reasons": reasons}

    def hypotheses(self, status: str | None = None) -> list[dict]:
        sql = (
            "SELECT id, author, claim, kind, evidence_refs_json, finding_ids_json, confidence, "
            "status, reasons_json FROM hypotheses WHERE agent_run_id = ?"
        )
        args: list = [self.agent_run_id]
        if status:
            sql += " AND status = ?"
            args.append(status)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY id", args).fetchall()
        return [
            {
                "id": r[0],
                "author": r[1],
                "claim": r[2],
                "kind": r[3],
                "evidence_refs": json.loads(r[4]),
                "finding_ids": json.loads(r[5]),
                "confidence": r[6],
                "status": r[7],
                "reasons": json.loads(r[8]),
            }
            for r in rows
        ]


def _clip_payload(payload: dict) -> dict:
    return {k: _clip(v) if isinstance(v, str) else v for k, v in payload.items()}
