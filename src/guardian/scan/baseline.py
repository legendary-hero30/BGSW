"""D1.S4: scanner-only baseline (PDF phase 1 exit test).

The baseline lists components, CVEs, severity and fix versions with dependency paths. Every
value comes from tool output or the offline feeds. Scanners run in an empty network namespace.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from guardian.scan.common import (
    Draft,
    EvidenceStore,
    assemble,
    excerpt,
    exploit_refs,
    fixed_by_tool,
    group_summary,
    pointer_excerpt,
    ref_of,
    sort_key,
)
from guardian.scan.feeds import EpssFeed, KevFeed
from guardian.scan.parsers import (
    VulnGroup,
)
from guardian.schemas.evidence import EvidenceKind, EvidenceRef
from guardian.schemas.finding import FindingSet, FindingType
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.risk import Exposure, RiskFactors
from guardian.schemas.sbom import DependencyScope
from guardian.store import DEFAULT_DB
from guardian.tools.runner import WORKSPACE, jail, run_tool, workspace_relative

CACHE = WORKSPACE / "cache"
SCANNERS = ("grype", "trivy", "osv-scanner")
DEPENDENCY_TYPES = frozenset(
    {
        FindingType.VULNERABLE_DIRECT,
        FindingType.VULNERABLE_TRANSITIVE,
        FindingType.MALICIOUS_PACKAGE,
    }
)
CONTEXT_TOOLS = frozenset({"dependency-graph", "epss", "cisa-kev", "oci-layout"})


def image_line(stats: dict | None) -> str:
    if not stats:
        return "none"
    return (
        f"{stats['image']}@{stats['manifest_digest'][:19]}… "
        f"({stats['groups']} advisory groups; Grype CPE-only matches excluded: "
        f"{stats['grype_cpe_only_excluded']})"
    )


# --- running the scanners (offline) --------------------------------------------------------


def run_full_sbom(target_root: Path, out: Path) -> Path:
    """Syft SBOM that includes dev dependencies (the input Grype scans)."""
    full_sbom = out / "sbom-full.cdx.json"
    run_tool(
        "syft",
        ["scan", f"dir:{jail(target_root)}", "-q", "-o", f"cyclonedx-json@1.5={jail(full_sbom)}"],
        env={"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"},
        offline=True,
    )
    return full_sbom


def run_one_scanner(scanner: str, target_root: Path, lockfile: Path, out: Path) -> Path:
    """Run one dependency scanner offline. ``grype`` needs sbom-full.cdx.json in ``out``."""
    path = out / f"{scanner.split('-')[0]}.json"
    if scanner == "grype":
        run_tool(
            "grype",
            ["sbom:" + str(jail(out / "sbom-full.cdx.json")), "-q", "-o", "json",
             "--file", str(jail(path))],
            env={"GRYPE_DB_CACHE_DIR": str(CACHE / "grype"), "GRYPE_DB_AUTO_UPDATE": "false"},
            offline=True,
        )  # fmt: skip
    elif scanner == "trivy":
        run_tool(
            "trivy",
            ["fs", "--scanners", "vuln", "--include-dev-deps", "--skip-db-update",
             "--skip-java-db-update", "--offline-scan", "--cache-dir", str(CACHE / "trivy"),
             "--quiet", "-f", "json", "-o", str(jail(path)), str(jail(target_root))],
            offline=True,
        )  # fmt: skip
    elif scanner == "osv-scanner":
        run_tool(
            "osv-scanner",
            ["scan", "source", "--offline", "--format", "json", "--output-file", str(jail(path)),
             "-L", str(jail(lockfile))],
            env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(CACHE / "osv")},
            offline=True,
            ok_codes=frozenset({0, 1}),  # 1 = vulnerabilities found
        )  # fmt: skip
    else:
        raise ValueError(f"unknown scanner {scanner!r}; choose from {SCANNERS}")
    return path


def run_scanners(target_root: Path, lockfile: Path, out: Path) -> dict[str, str]:
    """Run all three dependency scanners with no network. Returns output files by tool."""
    run_full_sbom(target_root, out)
    return {t: workspace_relative(run_one_scanner(t, target_root, lockfile, out)) for t in SCANNERS}


# --- mapping scanner results to the graph -------------------------------------------------------


@dataclass(frozen=True)
class Placement:
    node: str  # representative install path
    path: tuple[str, ...]  # node IDs, root first
    install_paths: tuple[str, ...]
    all_dev: bool


def place(graph: DependencyGraph, nodes_by_label: dict[str, list[str]], label: str):
    """Pick the representative install path: runtime before dev, direct first, then shortest."""
    candidates = nodes_by_label.get(label, [])
    if not candidates:
        return None
    scored = []
    for node_id in candidates:
        node = graph.node(node_id)
        runtime = node.scope is not DependencyScope.DEV
        path = (runtime and graph.shortest_path(node_id, exclude_dev=True)) or graph.shortest_path(
            node_id
        )
        if path is None:
            continue
        scored.append((not runtime, not bool(node.direct), len(path), node_id, path))
    if not scored:
        return None
    scored.sort()
    _, _, _, node_id, path = scored[0]
    all_dev = all(graph.node(n).scope is DependencyScope.DEV for n in candidates)
    return Placement(node_id, path, tuple(sorted(candidates)), all_dev)


# --- building findings ---------------------------------------------------------------------


def make_findings(
    groups: list[VulnGroup],
    graph: DependencyGraph,
    lockfile: str,
    outputs: dict[str, str],
    versions: dict[str, str],
    epss: EpssFeed,
    kev: KevFeed,
) -> tuple[FindingSet, list[str]]:
    store = EvidenceStore()
    drafts, unmapped = vuln_drafts(store, groups, graph, lockfile, outputs, versions, epss, kev)
    return assemble(store, drafts), unmapped


def vuln_drafts(
    store: EvidenceStore,
    groups: list[VulnGroup],
    graph: DependencyGraph,
    lockfile: str,
    outputs: dict[str, str],
    versions: dict[str, str],
    epss: EpssFeed,
    kev: KevFeed,
) -> tuple[list[Draft], list[str]]:
    """Drafts for dependency vulnerabilities, placed on the lockfile graph."""
    nodes_by_label: dict[str, list[str]] = {}
    for n in graph.nodes:
        if n.bom_ref != graph.root:
            nodes_by_label.setdefault(graph.label(n.bom_ref), []).append(n.bom_ref)

    drafts: list[Draft] = []
    unmapped: list[str] = []

    for group in groups:
        label = f"{group.name}@{group.version}"
        placement = place(graph, nodes_by_label, label)
        if placement is None:
            unmapped.append(f"{label} ({', '.join(sorted(group.ids))})")
            continue
        node = graph.node(placement.node)
        line = node.locations[0].line if node.locations else None
        refs: list[EvidenceRef] = []

        for m in sorted(group.matches, key=lambda x: (x.tool, x.advisory_id, x.pointer)):
            rec = store.add(
                ("scan", m.tool, m.pointer),
                kind=EvidenceKind.SCANNER_RESULT,
                tool=m.tool,
                tool_version=versions.get(m.tool),
                ref=m.advisory_id,
                file=lockfile,
                line=line,
                excerpt=pointer_excerpt(outputs[m.tool], m.pointer, m.summary),
            )
            refs.append(ref_of(rec))

        labels = graph.path_labels(placement.path)
        rec = store.add(
            ("graph", placement.node),
            kind=EvidenceKind.GRAPH_NODE,
            tool="dependency-graph",
            graph_node=placement.node,
            excerpt=excerpt(
                " > ".join(labels) + f" | install paths: {len(placement.install_paths)}"
            ),
        )
        refs.append(ref_of(rec))

        exploit, epss_value, kev_flag, in_kev = exploit_refs(store, group, epss, kev)
        refs.extend(exploit)
        malicious = group.malicious
        if malicious:
            ftype = FindingType.MALICIOUS_PACKAGE
        elif node.direct and len(placement.path) == 2:
            ftype = FindingType.VULNERABLE_DIRECT
        else:
            ftype = FindingType.VULNERABLE_TRANSITIVE

        draft = {
            "type": ftype,
            "title": excerpt(f"{label}: {group_summary(group)}", 200),
            "component": node.component,
            "dependency_path": labels,
            "introduced_by": tuple(graph.label(d) for d in graph.introduced_by(placement.node)),
            "advisory_ids": tuple(sorted(group.ids)),
            "severity": group.severity,
            "fixed_in": fixed_by_tool(group),
            "evidence": tuple(refs),
            "factors": RiskFactors(
                cvss=group.cvss,
                epss=epss_value,
                kev=kev_flag,
                exposure=Exposure.BUILD_OR_DEV if placement.all_dev else Exposure.UNKNOWN,
                confirmed_malicious=malicious,
            ),
        }
        drafts.append((sort_key(malicious, in_kev, group.severity, group.cvss, label, group),
                       draft))  # fmt: skip
    return drafts, unmapped


# --- orchestration ------------------------------------------------------------------------


def db_metadata(grype_output: str | Path | None) -> dict:
    """Vulnerability-data provenance. Grype's DB status comes from its own output, if it ran."""
    grype = {}
    if grype_output is not None:
        descriptor = json.loads(jail(grype_output).read_text()).get("descriptor", {})
        grype = descriptor.get("db", {}).get("status", {})
    trivy = json.loads((CACHE / "trivy" / "db" / "metadata.json").read_text())
    osv_zip = CACHE / "osv" / "osv-scalibr" / "npm" / "all.zip"
    feeds = json.loads((CACHE / "feeds" / "feeds.json").read_text())
    return {
        "grype_db": {"schema": grype.get("schemaVersion"), "built": grype.get("built")},
        "trivy_db": {"version": trivy.get("Version"), "updated_at": trivy.get("UpdatedAt")},
        "osv_npm_db": {
            "file": workspace_relative(osv_zip),
            "downloaded_at": datetime.fromtimestamp(osv_zip.stat().st_mtime, UTC).isoformat(
                timespec="seconds"
            ),
        },
        "feeds": feeds,
    }


def baseline(target_name: str, out_dir: str | Path, db: str | Path | None = DEFAULT_DB) -> dict:
    """The fixed, all-stages sequence. Used for regression, evaluation and the golden path.

    The agents do not use this: they call the same stages individually and choose their own
    order (see ``guardian.scan.pipeline.Pipeline``).
    """
    from guardian.scan.pipeline import Pipeline

    p = Pipeline(target_name, out_dir, db)
    p.sbom()
    for scanner in SCANNERS:
        p.scan(scanner)
    p.scan_dockerfile()
    p.scan_workflows()
    if (p.root / "Dockerfile").is_file():
        p.scan_image()
    p.anomaly_rules()
    return p.build_findings()


def render_markdown(summary: dict, fs: FindingSet) -> str:
    t = summary["target"]
    lines = [
        f"# Scanner-only baseline: {t['name']} @ {t['commit'][:12]}"
        + (" (SYNTHETIC seeded fork)" if summary.get("synthetic") else ""),
        "",
        f"Generated {summary['generated_at']}. Scanners ran offline (empty network namespace).",
        "Every value below comes from tool output or the cached EPSS and KEV feeds.",
        "Findings are ranked by risk score v1 (PDF formula; unknown factors are left out and the",
        "rest re-weighted, shown as coverage). Dependency counts cover the app's npm packages.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Findings | {summary['findings']} total |",
        f"| Dependency findings | {summary['dependency_findings']} "
        f"({summary['runtime_findings']} runtime, {summary['dev_only_findings']} dev-only) |",
        f"| Vulnerable packages | {summary['vulnerable_packages']} |",
        f"| By type | {summary['by_type']} |",
        f"| By severity | {summary['by_severity']} |",
        f"| In CISA KEV | {summary['kev_findings']} |",
        f"| Fix version available | {summary['with_fix']} |",
        f"| Raw matches per tool | {summary['raw_matches']} |",
        f"| Advisory groups found by 1/2/3 tools | {summary['groups_by_tool_count']} |",
        f"| Unmapped to graph | {len(summary['unmapped'])} |",
        f"| Image inspected | {image_line(summary.get('image'))} |",
        f"| CI/Dockerfile rule hits | {summary.get('posture_hits')} |",
        f"| Anomaly rule hits | {summary.get('anomaly_hits')} |",
        f"| By risk level | {summary.get('by_risk_level')} |",
        f"| Reachability | {summary.get('by_reachability')} |",
        f"| Exposure | {summary.get('by_exposure')} |",
        "",
        "| ID | Risk | Coverage | Type | Severity | CVSS | EPSS | KEV | Reach | Exposure | "
        "Provenance | Package | Dependency path | Fixed in | Tools | Evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for x in fs.findings:
        f = x.factors
        path = " > ".join(x.dependency_path)
        if len(x.dependency_path) > 5:
            path = " > ".join((*x.dependency_path[:2], "…", *x.dependency_path[-2:]))
        fixed = "; ".join(f"{fi.tool}: {', '.join(fi.versions)}" for fi in x.fixed_in) or "none"
        tools = sorted({e.tool for e in x.evidence if e.tool not in CONTEXT_TOOLS})
        r = x.risk
        risk = "" if r is None else f"{'' if r.score is None else r.score} {r.level.value}"
        lines.append(
            f"| {x.id} | {risk} | {'' if r is None else r.weight_coverage} | "
            f"{x.type.value} | {x.severity.value} | "
            f"{'' if f.cvss is None else f.cvss} | {'' if f.epss is None else f.epss} | "
            f"{'unknown' if f.kev is None else 'yes' if f.kev else 'no'} | "
            f"{f.reachability.value} | {f.exposure.value} | "
            f"{'' if f.provenance is None else f.provenance} | "
            f"{x.component.name}@{x.component.version} | {path} | {fixed} | "
            f"{', '.join(tools)} | {', '.join(e.evidence_id for e in x.evidence)} |"
        )
    return "\n".join(lines) + "\n"
