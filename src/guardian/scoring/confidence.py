"""Explainable confidence for a finding (Day 2: "an explainable risk score and confidence level").

Deterministic and derived only from stored facts: how many independent sources agree, how much
of the score rests on known data, and whether the evidence is a heuristic.
"""

from __future__ import annotations

from collections.abc import Mapping

from guardian.schemas.evidence import EvidenceRecord
from guardian.schemas.finding import Finding, FindingType

SCANNERS = frozenset({"grype", "trivy", "osv-scanner"})
HEURISTIC_TYPES = frozenset({FindingType.TYPOSQUAT, FindingType.UNEXPECTED_DEPENDENCY})


def finding_confidence(
    f: Finding, evidence: Mapping[str, EvidenceRecord] | None = None
) -> tuple[str, list[str]]:
    """Return ('high'|'medium'|'low', reasons). Each reason names a fact that moved the level."""
    points, reasons = 0, []
    tools = {e.tool for e in f.evidence}
    scanners = tools & SCANNERS
    if len(scanners) >= 3:
        points += 2
        reasons.append(
            f"{len(scanners)} independent scanners agree ({', '.join(sorted(scanners))})"
        )
    elif len(scanners) == 2:
        points += 1
        reasons.append(f"2 independent scanners agree ({', '.join(sorted(scanners))})")
    elif len(scanners) == 1:
        reasons.append(f"only one scanner reported it ({next(iter(scanners))})")
    elif "guardian-rules" in tools or "zizmor" in tools or "hadolint" in tools:
        points += 1
        reasons.append("a deterministic rule reported it; no CVE database is involved")

    coverage = f.risk.weight_coverage if f.risk else 0.0
    if coverage >= 0.9:
        points += 2
        reasons.append(f"score rests on {coverage:.0%} of the risk factors")
    elif coverage >= 0.65:
        points += 1
        reasons.append(f"score rests on {coverage:.0%} of the risk factors")
    else:
        points -= 1
        unknown = ", ".join(f.risk.unknown_factors) if f.risk else "all"
        reasons.append(
            f"score rests on only {coverage:.0%} of the risk factors (unknown: {unknown})"
        )

    if f.type in HEURISTIC_TYPES:
        points -= 1
        reasons.append("this is a heuristic signal, not a confirmed advisory")
    if f.factors.confirmed_malicious:
        points += 1
        reasons.append("confirmed by a malicious-package advisory")
    if f.factors.reachability.value == "unknown":
        reasons.append("reachability is unknown for this kind of finding")

    level = "high" if points >= 3 else "medium" if points >= 1 else "low"
    return level, reasons
