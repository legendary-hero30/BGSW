"""Remediation proposal contract (AGENTS.md section 5) and validation result."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from guardian.schemas.common import GuardianModel


class ActionKind(StrEnum):
    UPGRADE = "upgrade"
    REPLACE = "replace"
    REMOVE = "remove"
    PIN = "pin"
    UPDATE_BASE_IMAGE = "update_base_image"
    BLOCK = "block"
    ESCALATE = "escalate"  # request security review; no automated change


class ProposalStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    VALIDATED = "validated"
    FAILED = "failed"


class Edit(GuardianModel):
    """One change to package.json. Exact, reversible, and derived only from tool-reported data."""

    file: str = "package.json"
    op: Literal["set_dependency", "set_override"]
    section: str  # dependencies | devDependencies | optionalDependencies | overrides
    package: str
    from_spec: str | None = None
    to_spec: str


class RiskReduction(GuardianModel):
    findings_resolved: tuple[str, ...]
    highest_score_resolved: float | None
    highest_level_resolved: str | None
    note: str


class Compatibility(GuardianModel):
    level: Literal["low", "medium", "high", "unknown"]
    reasons: tuple[str, ...]


class Alternative(GuardianModel):
    action: ActionKind
    why_not_chosen: str


class Proposal(GuardianModel):
    id: str = ""  # assigned by the store
    run_id: str
    finding_id: str  # the finding that triggered it
    package: str | None = None
    current_version: str | None = None
    action: ActionKind
    target: str | None = None  # the version or reference to move to; None when unknown
    summary: str = Field(min_length=10, max_length=400)
    justification: str | None = Field(default=None, max_length=1200)  # agent-written, gated
    expected_risk_reduction: RiskReduction
    compatibility: Compatibility
    rollback: tuple[str, ...] = Field(min_length=1)
    alternatives_considered: tuple[Alternative, ...] = ()
    evidence_refs: tuple[str, ...]  # E-#### ids of the triggering finding
    edits: tuple[Edit, ...] = ()
    applicable: bool = False  # True only when edits fully express the change
    needs: tuple[str, ...] = ()  # what is missing before it could be applied
    confidence: Literal["high", "medium", "low"] = "medium"
