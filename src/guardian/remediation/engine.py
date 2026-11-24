"""Deterministic remediation proposals.

Every version and number comes from scanner output or the stored risk assessment. Where a fix
cannot be known without a registry lookup (a base-image digest, an action's commit SHA, the
parent version that bumps a transitive), the proposal says so in ``needs`` instead of guessing.
A model may add a grounded ``justification``; it never chooses the target.
"""

from __future__ import annotations

from collections.abc import Mapping

from guardian.remediation.schemas import (
    ActionKind,
    Alternative,
    Compatibility,
    Edit,
    Proposal,
    RiskReduction,
)
from guardian.remediation.semver import Version, change_kind, find_all, parse
from guardian.schemas.evidence import EvidenceRecord
from guardian.schemas.finding import Finding, FindingSet, FindingType
from guardian.scoring.confidence import finding_confidence

VULN_TYPES = frozenset(
    {
        FindingType.VULNERABLE_DIRECT,
        FindingType.VULNERABLE_TRANSITIVE,
        FindingType.MALICIOUS_PACKAGE,
    }
)
DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
REVIEW_TYPES = frozenset(
    {
        FindingType.TYPOSQUAT,
        FindingType.INSTALL_SCRIPT,
        FindingType.LOCKFILE_CHANGE,
        FindingType.UNEXPECTED_DEPENDENCY,
        FindingType.SUSPICIOUS_UPDATE,
    }
)
RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


# Fix versions the scanners reported for a finding (never invented).
def fix_versions(f: Finding) -> list[Version]:
    out: list[Version] = []
    for fixed in f.fixed_in:
        for text in fixed.versions:
            out.extend(find_all(text))
    return sorted(set(out), key=Version.key)


# Smallest fix version that is above the current one: the least risky upgrade.
def lowest_fix(current: Version, fixes: list[Version]) -> Version | None:
    """The smallest strictly newer fix, preferring the same major line (least breaking)."""
    newer = [v for v in fixes if current < v]
    same_major = [v for v in newer if v.major == current.major]
    pool = same_major or newer
    return pool[0] if pool else None


# Find which package.json section (dependencies, devDependencies...) holds a package.
def find_section(manifest: Mapping | None, name: str) -> tuple[str, str] | None:
    if not manifest:
        return None
    for section in DEP_SECTIONS:
        spec = (manifest.get(section) or {}).get(name)
        if isinstance(spec, str):
            return section, spec
    return None


# Version spec for the target, keeping the original range style (^, ~ or exact).
def new_spec(old: str, target: Version) -> str:
    """Keep a ^ or ~ prefix; otherwise pin exactly."""
    return f"{old[0]}{target}" if old[:1] in {"^", "~"} else str(target)


# Estimate compatibility impact from semver alone; build and tests have not run yet.
def _compat(
    current: Version, target: Version, *, transitive: bool, dev_only: bool
) -> Compatibility:
    kind = change_kind(current, target)
    reasons = ["estimated from semantic versioning only; build and tests have not run"]
    level = {"patch": "low", "minor": "low", "major": "high"}.get(kind, "unknown")
    if kind == "major":
        reasons.append(
            f"major version change {current.major} -> {target.major}: breaking changes allowed"
        )
    elif current.major == 0 and kind in {"minor", "patch"}:
        level = "medium" if kind == "minor" else "low"
        reasons.append("0.x versions may break on any minor change")
    else:
        reasons.append(f"{kind} release within major {current.major}")
    if transitive:
        level = {"low": "medium", "medium": "high"}.get(level, level)
        reasons.append(
            "applied as an npm override: every consumer in the tree is forced to this version, "
            "including packages whose declared range did not allow it"
        )
    if dev_only:
        reasons.append("development dependency: production behaviour is not affected")
    return Compatibility(level=level, reasons=tuple(reasons))


# Plain-language rollback steps for a proposal.
def _rollback(branch_hint: str, applicable: bool) -> tuple[str, ...]:
    if not applicable:
        return ("No file is changed by this proposal, so there is nothing to roll back.",)
    return (
        f"Delete branch {branch_hint}, or revert its commit (git revert <commit>).",
        "Restore package.json and package-lock.json from the base commit.",
        "Nothing is merged without a human, so the main branch is untouched until then.",
    )


# All findings that the same package change would resolve.
def _group(fs: FindingSet, f: Finding) -> list[Finding]:
    return [
        g
        for g in fs.findings
        if g.type in VULN_TYPES
        and g.component.name == f.component.name
        and g.component.version == f.component.version
    ]


# Build one fix proposal for a finding from tool data. Pure: no files are written.
def propose(
    fs: FindingSet,
    finding_id: str,
    manifest: Mapping | None,
    *,
    run_id: str,
    justification: str | None = None,
) -> Proposal:
    f = next((x for x in fs.findings if x.id == finding_id), None)
    if f is None:
        raise KeyError(f"unknown finding {finding_id}")
    evidence: Mapping[str, EvidenceRecord] = {r.id: r for r in fs.evidence}
    level, _ = finding_confidence(f, evidence)
    base = {
        "run_id": run_id,
        "finding_id": f.id,
        "package": f.component.name,
        "current_version": f.component.version,
        "justification": justification,
        "evidence_refs": tuple(e.evidence_id for e in f.evidence),
        "confidence": level,
    }
    label = f"{f.component.name}@{f.component.version}"

    if f.type in VULN_TYPES and not f.factors.confirmed_malicious:
        current = parse(f.component.version or "")
        group = _group(fs, f)
        targets = []
        unfixed = []
        for g in group:
            t = lowest_fix(current, fix_versions(g)) if current else None
            (targets if t else unfixed).append((g, t))
        if current and targets:
            target = max(t for _, t in targets if t is not None)
            resolved = [g for g, t in targets if t is not None and t <= target]
            section = find_section(manifest, f.component.name)
            transitive = section is None
            if manifest is None:
                edit, applicable, needs = None, False, ("package.json of the target",)
            elif section:
                edit = Edit(
                    op="set_dependency",
                    section=section[0],
                    package=f.component.name,
                    from_spec=section[1],
                    to_spec=new_spec(section[1], target),
                )
                applicable, needs = True, ()
            else:
                edit = Edit(
                    op="set_override",
                    section="overrides",
                    package=f.component.name,
                    from_spec=None,
                    to_spec=str(target),
                )
                applicable, needs = True, ()
            scores = [g.risk.score for g in resolved if g.risk and g.risk.score is not None]
            levels = [g.risk.level.value for g in resolved if g.risk]
            top_level = max(levels, key=lambda x: RANK.get(x, 0), default=None)
            direct_word = "direct" if not transitive else "transitive, via override"
            alternatives = [
                Alternative(
                    action=ActionKind.ESCALATE,
                    why_not_chosen="every change already needs a named human's approval; "
                    "escalating adds nothing unless the approver disagrees with this fix",
                ),
                Alternative(
                    action=ActionKind.REMOVE,
                    why_not_chosen=(
                        f"{label} is imported by the application's server code"
                        if f.factors.reachability.value == "imported"
                        else "removal needs a code change Guardian cannot test"
                    ),
                ),
            ]
            if transitive and f.introduced_by:
                alternatives.insert(
                    0,
                    Alternative(
                        action=ActionKind.UPGRADE,
                        why_not_chosen="upgrading the introducing dependency "
                        f"({', '.join(f.introduced_by[:3])}) "
                        "could fix it without an override, but the parent version "
                        "that carries the fix is "
                        "unknown without a registry lookup",
                    ),
                )
            if unfixed:
                alternatives.append(
                    Alternative(
                        action=ActionKind.ESCALATE,
                        why_not_chosen=f"{', '.join(g.id for g, _ in unfixed)} on this package "
                        "report no "
                        "fixed version and would remain",
                    )
                )
            return Proposal(
                **base,
                action=ActionKind.UPGRADE,
                target=str(target),
                summary=f"Upgrade {f.component.name} {f.component.version} -> {target} "
                f"({direct_word}); resolves {len(resolved)} finding(s), highest {top_level}.",
                expected_risk_reduction=RiskReduction(
                    findings_resolved=tuple(g.id for g in resolved),
                    highest_score_resolved=max(scores) if scores else None,
                    highest_level_resolved=top_level,
                    note="Resolved means a scanner-reported fix version is at or below the target. "
                    "The rescan confirms it; the new version may have its own findings.",
                ),
                compatibility=_compat(
                    current,
                    target,
                    transitive=transitive,
                    dev_only=f.factors.exposure.value == "build_or_dev",
                ),
                rollback=_rollback(f"guardian/fix-{f.id}", applicable),
                alternatives_considered=tuple(alternatives),
                edits=(edit,) if edit else (),
                applicable=applicable,
                needs=needs,
            )
        return Proposal(
            **base,
            action=ActionKind.ESCALATE,
            target=None,
            summary=f"No scanner reports a fixed version of {label}: escalate for security review.",
            expected_risk_reduction=RiskReduction(
                findings_resolved=(),
                highest_score_resolved=None,
                highest_level_resolved=None,
                note="No automated change is proposed.",
            ),
            compatibility=Compatibility(level="unknown", reasons=("nothing is changed",)),
            rollback=_rollback("", False),
            alternatives_considered=(
                Alternative(
                    action=ActionKind.UPGRADE, why_not_chosen="no tool reports a fixed version"
                ),
                Alternative(
                    action=ActionKind.REMOVE,
                    why_not_chosen="needs a code change Guardian cannot test",
                ),
                Alternative(
                    action=ActionKind.BLOCK, why_not_chosen="no policy engine is configured"
                ),
            ),
            needs=("a security reviewer's decision",),
        )

    if f.factors.confirmed_malicious or f.type in REVIEW_TYPES:
        what = (
            "a confirmed malicious package"
            if f.factors.confirmed_malicious
            else f.type.value.replace("_", " ")
        )
        parents = ", ".join(f.introduced_by[:3]) or "its parent"
        return Proposal(
            **base,
            action=ActionKind.ESCALATE,
            target=None,
            summary=f"Escalate {label} ({what}) for security review before any change.",
            expected_risk_reduction=RiskReduction(
                findings_resolved=(),
                highest_score_resolved=None,
                highest_level_resolved=None,
                note="Review decides between removing, replacing or blocking.",
            ),
            compatibility=Compatibility(level="unknown", reasons=("nothing is changed",)),
            rollback=_rollback("", False),
            alternatives_considered=(
                Alternative(
                    action=ActionKind.REMOVE,
                    why_not_chosen=f"removing it means removing or "
                    f"changing {parents}, which needs a review of how the app uses it",
                ),
                Alternative(
                    action=ActionKind.REPLACE,
                    why_not_chosen="a replacement must be chosen by a person",
                ),
                Alternative(
                    action=ActionKind.BLOCK, why_not_chosen="no policy engine is configured"
                ),
            ),
            needs=("a security reviewer's decision",),
        )

    if f.type in {FindingType.UNTRUSTED_IMAGE, FindingType.VULNERABLE_IMAGE_PACKAGE}:
        return Proposal(
            **base,
            action=ActionKind.UPDATE_BASE_IMAGE,
            target=None,
            summary=f"Update the container base image to fix {label}; pin it by digest.",
            expected_risk_reduction=RiskReduction(
                findings_resolved=(),
                highest_score_resolved=None,
                highest_level_resolved=None,
                note="Depends on the image chosen; a rescan measures it.",
            ),
            compatibility=Compatibility(
                level="unknown", reasons=("a newer base image can change the runtime",)
            ),
            rollback=_rollback("", False),
            alternatives_considered=(
                Alternative(
                    action=ActionKind.PIN,
                    why_not_chosen="pinning the old image keeps its vulnerabilities",
                ),
            ),
            needs=(
                "a supported image tag and its digest (needs a registry lookup, not done offline)",
            ),
        )

    if f.type is FindingType.UNPINNED_CI:
        return Proposal(
            **base,
            action=ActionKind.PIN,
            target=None,
            summary=f"Pin {label} to a full commit SHA.",
            expected_risk_reduction=RiskReduction(
                findings_resolved=(),
                highest_score_resolved=None,
                highest_level_resolved=None,
                note="Removes the mutable-reference risk for this use.",
            ),
            compatibility=Compatibility(level="low", reasons=("pins the version already in use",)),
            rollback=_rollback("", False),
            alternatives_considered=(),
            needs=(
                "the commit SHA of the release in use (needs a network lookup, not done offline)",
            ),
        )

    return Proposal(
        **base,
        action=ActionKind.ESCALATE,
        target=None,
        summary=f"Escalate {label} ({f.type.value.replace('_', ' ')}) for review.",
        expected_risk_reduction=RiskReduction(
            findings_resolved=(),
            highest_score_resolved=None,
            highest_level_resolved=None,
            note="No automated change.",
        ),
        compatibility=Compatibility(level="unknown", reasons=("nothing is changed",)),
        rollback=_rollback("", False),
        needs=("a reviewer's decision",),
    )
