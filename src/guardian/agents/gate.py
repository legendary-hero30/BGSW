"""Deterministic gate for model-written explanations (PDF: 'Verify' step of the reasoning loop).

A model may only *explain* a finding. It cannot add facts. An explanation is accepted only
if every identifier, version and evidence citation in it already belongs to that finding, and
it states the reachability the deterministic pipeline computed. Rejected explanations are
returned to the model with reasons (so it can retry), recorded as rejected, and never shown.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from pydantic import Field, ValidationError

from guardian.schemas.common import EVIDENCE_ID_RE, EvidenceId, FindingId, GuardianModel
from guardian.schemas.evidence import EvidenceRecord
from guardian.schemas.finding import Finding
from guardian.schemas.risk import Reachability

# Broad shapes on purpose: an invented ID outside GitHub's real alphabet must still be caught.
ADVISORY_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b", re.IGNORECASE
)
# A version may end a sentence ("fixed in 4.17.21."), but is not followed by more version.
VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]*[0-9A-Za-z])?)(?!\w|\.\w)")
PKG_VERSION_RE = re.compile(
    r"(?<![\w/@.-])(@?[a-z0-9][a-z0-9._/-]*)@"
    r"(v?\d+(?:\.[0-9A-Za-z]+)*(?:[-+][0-9A-Za-z.-]*[0-9A-Za-z])?)",
    re.IGNORECASE,
)

# The phrase each computed reachability must be stated with (D8-03).
REACH_WORDS = {
    Reachability.CALLED: "called",
    Reachability.IMPORTED: "imported",
    Reachability.PRESENT_ONLY: "present",
    Reachability.DEV_ONLY_UNUSED: "dev",
    Reachability.UNKNOWN: "unknown",
}


# An agent's explanation of one finding, with the evidence ids it cites.
class Explanation(GuardianModel):
    """The PDF evidence card's 'AI explanation': why it matters, reachability, confidence."""

    finding_id: FindingId
    why_it_matters: str = Field(min_length=20, max_length=500)
    reachability: str = Field(min_length=5, max_length=300)
    confidence: Literal["high", "medium", "low"]
    confidence_reason: str = Field(min_length=5, max_length=300)
    cited_evidence: tuple[EvidenceId, ...] = Field(min_length=1, max_length=20)

    def text(self) -> str:
        return " ".join((self.why_it_matters, self.reachability, self.confidence_reason))

    def rationale(self) -> str:
        """Three sentences for Finding.rationale, ending with the citations."""
        cites = " ".join(f"[{e}]" for e in self.cited_evidence)
        return (
            f"{self.why_it_matters.rstrip('.')}. {self.reachability.rstrip('.')}. "
            f"Confidence {self.confidence}: {self.confidence_reason.rstrip('.')}. {cites}"
        )


@dataclass(frozen=True)
# The tool-reported facts an explanation is allowed to state.
class Facts:
    """Everything a piece of model text may mention, for one scope (a finding, several, a run)."""

    scope: str  # how rejections name it: "F-007", "F-001/F-002", "the run"
    evidence_ids: frozenset[str]
    advisories: frozenset[str]  # upper-case
    labels: frozenset[str]  # lower-case name@version
    versions: frozenset[str]


# Collect the facts (versions, IDs, fix versions) from the stored finding.
def facts_for(
    findings: Iterable[Finding],
    *,
    scope: str,
    extra_labels: Iterable[str] = (),
    evidence: Mapping[str, EvidenceRecord] | None = None,
) -> Facts:
    """Facts a text about ``findings`` may mention. Versions that appear in a finding's title or
    in its evidence excerpts are tool-reported text, so they count (e.g. an OS version)."""
    ev_ids: set[str] = set()
    advisories: set[str] = set()
    labels: set[str] = {x.lower() for x in extra_labels}
    versions: set[str] = {x.rsplit("@", 1)[-1].lstrip("v") for x in extra_labels if "@" in x}
    for f in findings:
        ev_ids |= {e.evidence_id for e in f.evidence}
        advisories |= {a.upper() for a in f.advisory_ids}
        own = (f"{f.component.name}@{f.component.version}", *f.dependency_path, *f.introduced_by)
        labels |= {x.lower() for x in own}
        versions |= {f.component.version or ""}
        versions |= {x.rsplit("@", 1)[-1] for x in own}
        for fixed in f.fixed_in:
            for v in fixed.versions:
                versions.update(VERSION_RE.findall(v) or [v])
        texts = [f.title]
        if evidence:
            texts += [r.excerpt or "" for e in f.evidence if (r := evidence.get(e.evidence_id))]
        for text in texts:
            versions.update(VERSION_RE.findall(text))
    return Facts(
        scope,
        frozenset(ev_ids),
        frozenset(advisories),
        frozenset(labels),
        frozenset(v.lstrip("v") for v in versions if v),
    )


# List claims in the text that are not backed by the facts or citations.
def grounding_problems(text: str, facts: Facts, cited: Iterable[str] = ()) -> list[str]:
    """Every identifier or version in ``text`` (and every ``cited`` ID) must be in ``facts``."""
    problems: list[str] = []
    for eid in sorted(set(cited) | set(EVIDENCE_ID_RE.findall(text))):
        if eid not in facts.evidence_ids:
            problems.append(f"cites {eid}, which is not evidence of {facts.scope}")
    for aid in sorted({a.upper() for a in ADVISORY_RE.findall(text)}):
        if aid not in facts.advisories:
            problems.append(f"mentions {aid}, which is not an advisory of {facts.scope}")
    for name, version in PKG_VERSION_RE.findall(text):
        if f"{name}@{version}".lower() not in facts.labels:
            problems.append(f"mentions {name}@{version}, which is not on {facts.scope}'s path")
    for v in sorted(set(VERSION_RE.findall(text))):
        if v.lstrip("v") not in facts.versions:
            problems.append(f"mentions version {v}, which no tool reported for {facts.scope}")
    return problems


# Accept an explanation only if every claim is grounded; otherwise return why not.
def gate(
    raw: dict,
    findings: dict[str, Finding],
    evidence: Mapping[str, EvidenceRecord] | None = None,
) -> tuple[Explanation | None, list[str]]:
    """Validate one explanation dict. Returns (explanation, []) or (None, reasons)."""
    try:
        exp = Explanation.model_validate(raw)
    except ValidationError as exc:
        return None, [f"schema: {e['loc']}: {e['msg']}" for e in exc.errors()][:10]
    f = findings.get(exp.finding_id)
    if f is None:
        return None, [f"unknown finding {exp.finding_id}"]

    reasons = grounding_problems(
        exp.text(), facts_for([f], scope=f.id, evidence=evidence), cited=exp.cited_evidence
    )
    word = REACH_WORDS[f.factors.reachability]
    if word not in exp.reachability.lower():
        reasons.append(
            f"reachability must state the computed value '{word}' ({f.factors.reachability.value})"
        )
    return (None, reasons) if reasons else (exp, [])
