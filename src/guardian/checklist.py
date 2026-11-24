"""Day 1 judging self-checklist (PDF section 10), evaluated against a stored run's artifacts.

Each item is 'pass', 'fail' or 'n/a' with the evidence it was decided on. Nothing is assumed.
Day 2 items (approval gate, before/after validation) are 'n/a' because Day 1 makes no changes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from guardian.agents.gate import gate
from guardian.scan.verify import verify_run
from guardian.schemas.finding import FindingType
from guardian.schemas.graph import DependencyGraph
from guardian.store import accepted_explanations, connect, load_findings
from guardian.tools.runner import WORKSPACE, jail

ANOMALY_TYPES = {
    FindingType.MALICIOUS_PACKAGE,
    FindingType.TYPOSQUAT,
    FindingType.INSTALL_SCRIPT,
    FindingType.LOCKFILE_CHANGE,
    FindingType.UNEXPECTED_DEPENDENCY,
    FindingType.UNTRUSTED_IMAGE,
    FindingType.UNPINNED_CI,
}
VULN_TYPES = {
    FindingType.VULNERABLE_DIRECT,
    FindingType.VULNERABLE_TRANSITIVE,
    FindingType.VULNERABLE_IMAGE_PACKAGE,
}


@dataclass(frozen=True)
class Item:
    n: int
    text: str
    status: str  # pass | fail | n/a
    evidence: str


def evaluate(run_id: str, db: str) -> list[Item]:
    out = jail(run_id)
    summary = json.loads((out / "baseline.json").read_text())
    conn = connect(db)
    try:
        fs = load_findings(conn, run_id)
        explained = accepted_explanations(conn, run_id)
    finally:
        conn.close()
    f = fs.findings
    graph = DependencyGraph.model_validate_json((out / "graph.json").read_text())
    sbom = json.loads((out / "sbom.cdx.json").read_text())
    items: list[Item] = []

    def add(text: str, ok: bool | None, evidence: str) -> None:
        status = "n/a" if ok is None else ("pass" if ok else "fail")
        items.append(Item(len(items) + 1, text, status, evidence))

    add(
        "SBOM generated in CycloneDX or SPDX and included in the submission",
        sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.5",
        f"{run_id}/sbom.cdx.json: {sbom.get('bomFormat')} {sbom.get('specVersion')}, "
        f"{len(sbom.get('components', []))} components",
    )

    depths = graph.depths()
    direct = sum(1 for n in graph.nodes if n.direct)
    transitive = sum(1 for d in depths.values() if d >= 2)
    unversioned = [
        n.bom_ref for n in graph.nodes if n.bom_ref != graph.root and not n.component.version
    ]
    add(
        "Direct and transitive dependencies captured with names and versions",
        direct > 0 and transitive > 0 and not unversioned,
        f"{direct} direct and {transitive} transitive install paths; "
        f"{len(unversioned)} without a version",
    )

    unreachable = [n.bom_ref for n in graph.nodes if n.bom_ref not in depths]
    unlocated = [n.bom_ref for n in graph.nodes if not n.locations]
    add(
        "Dependency graph with origin of each component",
        not unreachable and not unlocated,
        f"{len(graph.nodes)} nodes, {len(graph.edges)} edges; {len(unreachable)} unreachable "
        f"from the app root; {len(unlocated)} without a lockfile location",
    )

    ci_files = summary.get("outputs", {}).get("zizmor")
    image = summary.get("image")
    add(
        "At least one container image and one CI/CD workflow inspected",
        bool(image) and bool(ci_files),
        f"image {image['image'] + '@' + image['manifest_digest'][:19] if image else 'none'}; "
        f"workflows scanned by zizmor: {bool(ci_files)}; "
        f"{sum(1 for x in f if x.type is FindingType.UNPINNED_CI)} CI findings",
    )

    vulns = [x for x in f if x.type in VULN_TYPES]
    missing = [x.id for x in vulns if not x.advisory_ids]
    add(
        "CVE, severity and fix availability captured per vulnerability",
        bool(vulns) and not missing,
        f"{len(vulns)} vulnerability findings, all with advisory IDs and a severity label; "
        f"{sum(1 for x in vulns if x.fixed_in)} with a tool-reported fix version, "
        f"{sum(1 for x in vulns if not x.fixed_in)} with none reported",
    )

    trans = [x for x in f if x.type is FindingType.VULNERABLE_TRANSITIVE]
    untraced = [x.id for x in trans if len(x.dependency_path) < 3 or not x.introduced_by]
    add(
        "Transitive vulnerabilities traced to their source",
        bool(trans) and not untraced,
        f"{len(trans)} transitive findings with root-to-package paths and the direct "
        f"dependencies that introduce them; {len(untraced)} untraced",
    )

    anomalies = sorted({x.type.value for x in f if x.type in ANOMALY_TYPES})
    add(
        "At least one non-CVE supply-chain anomaly detected",
        bool(anomalies),
        f"types: {', '.join(anomalies) or 'none'}",
    )

    incomplete = [x.id for x in f if not x.evidence or x.risk is None]
    pkg_no_path = [x.id for x in f if x.type in VULN_TYPES and not x.dependency_path]
    add(
        "Evidence shows component, dependency path, supporting evidence and risk level",
        not incomplete and not pkg_no_path,
        f"{len(f)} findings; {len(incomplete)} missing evidence or risk; "
        f"{len(pkg_no_path)} vulnerability findings without a path",
    )

    v = verify_run(run_id)
    by_id = {x.id: x for x in f}
    evidence = {r.id: r for r in fs.evidence}
    regated = [fid for fid, exp in explained.items() if gate(exp, by_id, evidence)[1]]
    agent_ran = bool(explained) or (out / "agent-run.json").exists()
    add(
        "AI recommendations are grounded, with zero unresolved citations",
        None if not agent_ran else (not regated and not v.failures),
        (
            f"{len(explained)} accepted explanations, {len(regated)} failing a re-check; "
            f"cited facts resolved {v.resolved}/{v.checked}"
            if agent_ran
            else "no agent run on this stored run, so there are no AI recommendations to ground"
        ),
    )

    add(
        "Human approval gate visible before any change",
        None,
        "Day 2: Day 1 makes no changes to any repository",
    )
    add(
        "Validation shows risk reduced and no new issues introduced",
        None,
        "Day 2: remediation and rescans are not part of Day 1",
    )

    readme = WORKSPACE / "README.md"
    add(
        "README documents repo, setup steps, dependencies and tools used",
        readme.exists(),
        "README.md present"
        if readme.exists()
        else "README.md not written yet (AGENTS.md requires an approved step for it); setup is "
        "documented in SETUP.md",
    )
    return items


def as_dict(items: list[Item]) -> dict:
    counts = {s: sum(1 for i in items if i.status == s) for s in ("pass", "fail", "n/a")}
    return {"counts": counts, "items": [asdict(i) for i in items]}
