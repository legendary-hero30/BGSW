"""Validate an approved proposal: apply on a branch, rescan offline, diff, decide a verdict.

Verdicts (AGENTS.md section 8: "verified" needs all of the following):
  verified            the original finding is gone, no new Critical/High, build and tests passed,
                      and every SBOM change is explained by the proposal
  partially_verified  the finding is gone and nothing new is Critical/High, but build or tests
                      did not run (they need the sandbox and the registry)
  failed              the finding remains, a new Critical/High appeared, or a build/test failed
  blocked             the change could not be applied or rescanned (reason given)
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from guardian.remediation import execute, lockfile, workspace
from guardian.remediation.proposals import (
    ApprovalError,
    add_validation,
    get_proposal,
    now,
    require_approved,
)
from guardian.remediation.schemas import Proposal
from guardian.schemas.finding import Finding, FindingSet
from guardian.store import connect, load_findings
from guardian.tools.runner import jail

HIGH = {"Critical", "High"}
ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]


def component_set(sbom_path: Path) -> dict[str, str]:
    doc = json.loads(sbom_path.read_text())
    return {
        f"{c.get('name')}@{c.get('version')}": c.get("purl") or ""
        for c in doc.get("components", [])
        if c.get("name")
    }


# Components added, removed or changed between two SBOMs.
def sbom_diff(before: Path, after: Path) -> dict:
    b, a = component_set(before), component_set(after)
    names_b, names_a = {k.rsplit("@", 1)[0] for k in b}, {k.rsplit("@", 1)[0] for k in a}
    added = sorted(set(a) - set(b))
    removed = sorted(set(b) - set(a))
    changed = sorted(
        n for n in names_b & names_a
        if {k for k in b if k.rsplit("@", 1)[0] == n} != {k for k in a if k.rsplit("@", 1)[0] == n}
    )  # fmt: skip
    return {
        "components_before": len(b),
        "components_after": len(a),
        "added": added,
        "removed": removed,
        "version_changed": changed,
    }


log = logging.getLogger("guardian.validate")

WORK_PREFIX = re.compile(r"^targets/(?:work|dynamic)/[^/]+/")


def cname(f: Finding) -> str:
    """Component name with the scan directory removed: a Dockerfile or workflow finding is named
    by its path, which differs between the original checkout and the work copy."""
    return WORK_PREFIX.sub("", f.component.name)


def key(f: Finding) -> tuple:
    return (f.type.value, cname(f), tuple(sorted(f.advisory_ids)))


# Count findings by risk level, in severity order.
def levels(fs: FindingSet) -> dict[str, int]:
    c = Counter((f.risk.level.value if f.risk else "Unknown") for f in fs.findings)
    return {lvl: c[lvl] for lvl in ORDER if c[lvl]}


# Highest risk score in a finding set.
def top_score(fs: FindingSet) -> float | None:
    scores = [f.risk.score for f in fs.findings if f.risk and f.risk.score is not None]
    return max(scores) if scores else None


# Compare scans before and after: resolved, remaining and new findings.
def findings_diff(before: FindingSet, after: FindingSet, proposal: Proposal) -> dict:
    after_adv = {a for f in after.findings for a in f.advisory_ids}
    after_keys = {key(f) for f in after.findings}
    resolved, remaining = [], []
    targets = set(proposal.expected_risk_reduction.findings_resolved) | {proposal.finding_id}
    for f in before.findings:
        gone = key(f) not in after_keys and not (
            f.advisory_ids and set(f.advisory_ids) & after_adv
            and any(cname(g) == cname(f) for g in after.findings)
        )  # fmt: skip
        (resolved if gone else remaining).append(f)
    before_keys = {key(f) for f in before.findings}
    before_adv = {(cname(f), a) for f in before.findings for a in f.advisory_ids}
    new = [
        f for f in after.findings
        if key(f) not in before_keys
        and not any((cname(f), a) in before_adv for a in f.advisory_ids)
    ]  # fmt: skip

    def row(f: Finding) -> dict:
        return {
            "id": f.id, "type": f.type.value, "component": cname(f),
            "version": f.component.version, "advisories": list(f.advisory_ids),
            "level": f.risk.level.value if f.risk else "Unknown",
            "score": f.risk.score if f.risk else None,
        }  # fmt: skip

    return {
        "targeted": sorted(targets),
        "targeted_resolved": sorted(f.id for f in resolved if f.id in targets),
        "targeted_remaining": sorted(f.id for f in remaining if f.id in targets),
        "resolved": [row(f) for f in resolved],
        "remaining": [row(f) for f in remaining],
        "new": [row(f) for f in new],
    }


# Conservative verdict: verified only if every AGENTS.md criterion held.
def verdict_for(d: dict, steps: dict, sbom: dict, proposal: Proposal) -> tuple[str, list[str]]:
    why: list[str] = []
    if d["targeted_remaining"]:
        why.append(f"original finding still present: {', '.join(d['targeted_remaining'])}")
    new_high = [f for f in d["new"] if f["level"] in HIGH]
    if new_high:
        why.append(f"{len(new_high)} new Critical/High finding(s): {new_high[0]['component']}")
    if any(s["status"] == "failed" for s in steps.values()):
        why.append("a build or test step failed")
    if why:
        return "failed", why
    expected = {proposal.package} if proposal.package else set()
    unexplained = [
        n for n in [*sbom["added"], *sbom["removed"]]
        if n.rsplit("@", 1)[0] not in expected
    ]  # fmt: skip
    notes = []
    if unexplained:
        notes.append(
            f"{len(unexplained)} SBOM component change(s) go beyond the upgraded package "
            "(transitive dependencies moved with it); listed in the SBOM diff"
        )
    not_run = [n for n, s in steps.items() if s["status"] == "not_run"]
    if not_run:
        notes.append("not verified: " + ", ".join(not_run) + " did not run")
        return "partially_verified", notes
    if unexplained:
        return "partially_verified", notes
    return "verified", ["every AGENTS.md verification criterion held"]


# Build and test in the sandbox, on the fix and on an unmodified copy for attribution.
def build_test_steps(after_dir: Path, base_dir: Path | None) -> dict:
    """Build and tests execute untrusted code, so they run only in the namespace sandbox. The
    same steps run on an unmodified copy so a failure can be attributed to the fix or not."""
    out: dict = {}
    try:
        execute.install(after_dir)
        if base_dir is not None:
            execute.install(base_dir)
    except lockfile.RegistryAccessError as e:
        why = {"status": "not_run", "detail": str(e)}
        return {"build": why, "tests": why}
    for name in ("build", "test"):
        after = execute.step(after_dir, name)
        if base_dir is not None and after["status"] == "failed":
            after = execute.attribute(after, execute.step(base_dir, name))
        out["tests" if name == "test" else name] = after
    return out


# Apply an approved fix on a branch, rescan offline, diff, and record a verdict.
def validate(
    db: str,
    run_id: str,
    proposal_id: str,
    base_target: str,
    out_dir: str,
    *,
    on_step: Callable[[str], None] | None = None,
) -> dict:
    """Apply, rescan, diff, verdict. Raises ApprovalError unless a human approved this proposal."""
    from guardian.scan import baseline as bl
    from guardian.scan.pipeline import Pipeline

    trail: list[dict] = []  # what happened and when; stored in the report so it can be replayed

    def say(msg: str) -> None:
        log.info("validate %s %s: %s", run_id, proposal_id, msg)
        trail.append({"at": now(), "msg": msg})
        if on_step:
            on_step(msg)

    conn = connect(db)
    try:
        approval = require_approved(conn, run_id, proposal_id)
        p = get_proposal(conn, f"{run_id}:{proposal_id}" if ":" not in proposal_id else proposal_id)
        before = load_findings(conn, run_id)
    finally:
        conn.close()

    report: dict = {
        "proposal": json.loads(p.model_dump_json()),
        "approval": approval,
        "steps": {},
        "progress": trail,
        "inference_note": "Everything below except 'justification' is tool output or arithmetic.",
    }

    def blocked(reason: str) -> dict:
        report.update(verdict="blocked", reasons=[reason])
        c = connect(db)
        try:
            add_validation(c, run_id, p.id, report)
        finally:
            c.close()
        return report

    say(f"Approval confirmed: {approval['approver']} approved {proposal_id} (hash matches)")
    say("Creating the isolated work copy and applying the approved edit")
    try:
        ws = workspace.create(base_target, p)
    except workspace.WorkspaceError as e:
        return blocked(f"could not apply the change: {e}")
    report["branch"] = {k: ws[k] for k in ("branch", "commit", "path")}
    report["diff"] = ws["diff"]

    say("Regenerating package-lock.json (the one networked step)")
    try:
        report["steps"]["lockfile"] = {"status": "passed", **lockfile.regenerate(jail(ws["path"]))}
    except lockfile.RegistryAccessError as e:
        report["steps"]["lockfile"] = {"status": "not_run", "detail": str(e)}
        return blocked(f"lockfile not regenerated, so no rescan is meaningful: {e}")

    say("Rescanning the work copy offline")
    before_out = jail(out_dir)
    cov = {}
    if (before_out / "baseline.json").is_file():
        cov = json.loads((before_out / "baseline.json").read_text()).get("coverage", {})
    scanners = cov.get("scanners_run") or list(bl.SCANNERS)
    pipe = Pipeline(ws["target"], f"{out_dir}-after-{p.id.lower()}", None)
    try:
        pipe.sbom()
        for s in scanners:
            pipe.scan(s)
        if cov.get("dockerfile_scanned", True):
            pipe.scan_dockerfile()
        if cov.get("workflows_scanned", True):
            pipe.scan_workflows()
        if cov.get("anomaly_rules_run", True):
            pipe.anomaly_rules()
        pipe.build_findings()
    except Exception as e:
        return blocked(f"rescan failed: {type(e).__name__}: {e}")
    after = FindingSet.model_validate_json((pipe.out / "findings.json").read_text())
    report["steps"]["rescan"] = {"status": "passed", "scanners": scanners}

    before_sbom = before_out / "sbom.cdx.json"
    sbom = (
        sbom_diff(before_sbom, pipe.out / "sbom.cdx.json")
        if before_sbom.is_file() and (pipe.out / "sbom.cdx.json").is_file()
        else {"components_before": 0, "components_after": 0, "added": [], "removed": [],
              "version_changed": []}
    )  # fmt: skip
    diff = findings_diff(before, after, p)
    say("Building and testing in the sandbox (and on an unmodified copy for comparison)")
    base_dir = workspace.baseline_copy(base_target, p)
    report["steps"].update(build_test_steps(jail(ws["path"]), base_dir))
    report["sbom_diff"] = sbom
    report["findings_diff"] = diff
    report["risk"] = {
        "before": {"levels": levels(before), "top_score": top_score(before),
                   "findings": len(before.findings)},
        "after": {"levels": levels(after), "top_score": top_score(after),
                  "findings": len(after.findings)},
    }  # fmt: skip
    report["verdict"], report["reasons"] = verdict_for(diff, report["steps"], sbom, p)
    log.info("validate %s %s verdict=%s", run_id, proposal_id, report["verdict"])
    report["final_confidence"] = (
        "high" if report["verdict"] == "verified" else
        "medium" if report["verdict"] == "partially_verified" else "low"
    )  # fmt: skip
    report["remaining_risk"] = diff["remaining"]
    c = connect(db)
    try:
        add_validation(c, run_id, p.id, report)
    finally:
        c.close()
    return report


__all__ = ["ApprovalError", "validate"]
