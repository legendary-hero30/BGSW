"""Granular, idempotent deterministic stages over one target and one run directory.

This is the agents' toolbox, not a workflow. Each public method does one thing, returns a small
JSON-able summary, records its raw tool output under the run directory, and may be called in any
order and repeatedly. ``build_findings`` correlates whatever raw output exists into the
schema-validated, risk-scored FindingSet and stores it. It refuses to run when nothing has been
scanned: no output is never treated as "no findings".

``guardian.scan.baseline.baseline`` composes these stages in a fixed order; it is kept as the
regression and evaluation path. The agents decide their own sequence.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from guardian.sbom.build import build as build_sbom
from guardian.sbom.build import discover, load_target
from guardian.sbom.npm_lock import parse_lockfile
from guardian.scan import baseline as bl
from guardian.scan.anomaly import (
    AnomalyHit,
    TopList,
    anomaly_drafts,
    diff_rules,
    single_commit_rules,
)
from guardian.scan.common import EvidenceStore, assemble
from guardian.scan.context import enrich, resolve_top_level, scan_app
from guardian.scan.feeds import load_epss, load_kev
from guardian.scan.parsers import correlate, parse_grype, parse_osv, parse_trivy
from guardian.scan.posture import (
    ConfigHit,
    config_drafts,
    dockerfile_rules,
    eosl_hit,
    has_workflows,
    image_drafts,
    load_image,
    parse_from_lines,
    parse_hadolint,
    parse_trivy_config,
    parse_zizmor,
    run_dockerfile_tools,
    run_image_tools,
    run_workflow_tools,
    workflow_rules,
)
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.risk import Exposure
from guardian.store import DEFAULT_DB, connect, save_run
from guardian.tools.runner import jail, tool_version, workspace_relative

PARSERS = {"grype": parse_grype, "trivy": parse_trivy, "osv-scanner": parse_osv}
TOP_HITS = 15


class StageError(RuntimeError):
    """A stage cannot run yet or failed. The message is written for the agent to act on."""


class Pipeline:
    def __init__(self, target_name: str, out_dir: str | Path, db: str | Path | None = DEFAULT_DB):
        self.target_name = target_name
        self.target = load_target(target_name)
        self.out = jail(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.root = jail(self.target["path"])
        self.lockfile = jail(Path(self.target["path"]) / self.target["lockfile"])
        self.db = db
        self.run_id = workspace_relative(self.out)
        self.outputs: dict[str, str] = {}
        self.versions: dict[str, str] = {}
        self.sbom_summary: dict | None = None
        self.config_hits: dict[str, list[ConfigHit]] = {}
        self.anomalies: list[AnomalyHit] = []
        self.anomalies_done = False
        self.image_ctx: tuple[dict, object] | None = None  # (image record, final FROM line)
        self.image_stats: dict | None = None
        self.stages: dict[str, str] = {}  # stage name -> one-line result, for coverage reporting
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()

    @contextmanager
    def _stage(self, name: str) -> Iterator[None]:
        """Agents run in parallel. A stage runs once at a time; a second caller waits for the
        first and then sees its (cached or freshly written) result."""
        with self._locks_guard:
            lock = self._locks.setdefault(name, threading.RLock())
        with lock:
            yield

    # -- inventory ---------------------------------------------------------------------------
    def discover_files(self) -> dict:
        with self._stage("discover"):
            return self._discover_files()

    def _discover_files(self) -> dict:
        files = discover(self.root)
        t = self.target
        self.stages["discover_files"] = f"{sum(len(v) for v in files.values())} files"
        return {
            "target": {k: t.get(k) for k in ("name", "repo", "commit", "ecosystem", "license")},
            "lockfile": t["lockfile"],
            "files": files,
        }

    def sbom(self) -> dict:
        with self._stage("sbom"):
            return self._sbom()

    def _sbom(self) -> dict:
        """CycloneDX SBOM (Syft), lockfile dependency graph, cross-check. Idempotent."""
        if self.sbom_summary is None:
            self.sbom_summary = build_sbom(self.target_name, self.out)
            self.versions["syft"] = tool_version("syft")
            self.stages["sbom"] = f"{self.sbom_summary['sbom']['components']} components"
        s = self.sbom_summary
        g = s["graph"]
        return {
            "sbom_file": s["artifacts"]["sbom"]["file"],
            "components": s["sbom"]["components"],
            "graph": {k: g[k] for k in ("nodes", "edges", "max_depth", "unique_runtime_packages",
                                         "unique_dev_packages")},
            "direct_runtime": g["direct"]["runtime"],
            "direct_dev": g["direct"]["dev"],
            "cross_check_agrees": s["cross_check_vs_sbom"]["agrees"],
            "ci_actions": s["sbom"]["ci_actions"],
        }  # fmt: skip

    def graph(self) -> DependencyGraph:
        path = self.out / "graph.json"
        if not path.exists():
            raise StageError("no dependency graph yet: call generate_sbom first")
        return DependencyGraph.model_validate_json(path.read_text())

    # -- vulnerability scanning ----------------------------------------------------------------
    def scan(self, scanner: str) -> dict:
        with self._stage(f"scan:{scanner}"):
            return self._scan(scanner)

    def _scan(self, scanner: str) -> dict:
        """Run one offline dependency scanner (grype, trivy or osv-scanner)."""
        if scanner not in bl.SCANNERS:
            raise StageError(f"unknown scanner {scanner!r}; choose from {list(bl.SCANNERS)}")
        if scanner == "grype" and not (self.out / "sbom-full.cdx.json").exists():
            bl.run_full_sbom(self.root, self.out)
        path = bl.run_one_scanner(scanner, self.root, self.lockfile, self.out)
        self.outputs[scanner] = workspace_relative(path)
        self.versions[scanner] = tool_version(scanner)
        raw = PARSERS[scanner](path)
        ids = {m.advisory_id for m in raw}
        self.stages[f"scan:{scanner}"] = f"{len(raw)} matches"
        return {
            "scanner": scanner,
            "version": self.versions[scanner],
            "matches": len(raw),
            "distinct_advisories": len(ids),
            "affected_packages": len({(m.name, m.version) for m in raw}),
            "by_severity": dict(Counter(m.severity.value for m in raw)),
            "with_fix": sum(1 for m in raw if m.fixed),
            "malicious_advisories": sorted({m.advisory_id for m in raw if m.malicious}),
            "output": self.outputs[scanner],
        }

    # -- container and CI -------------------------------------------------------------------
    @staticmethod
    def _brief(hits: list[ConfigHit]) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        ranked = sorted(hits, key=lambda h: (order[h.severity.value], h.file, h.line or 0))
        return [
            {"tool": h.tool, "rule": h.rule, "severity": h.severity.value, "file": h.file,
             "line": h.line, "message": h.message[:200]}
            for h in ranked[:TOP_HITS]
        ]  # fmt: skip

    def scan_dockerfile(self) -> dict:
        with self._stage("dockerfile"):
            return self._scan_dockerfile()

    def _scan_dockerfile(self) -> dict:
        dockerfile = self.root / "Dockerfile"
        if not dockerfile.is_file():
            self.config_hits["dockerfile"] = []
            self.stages["scan_dockerfile"] = "no Dockerfile"
            return {"dockerfile": False, "note": "the target has no Dockerfile"}
        files = run_dockerfile_tools(self.root, self.out)
        self.outputs.update(files)
        self.versions.update({t: tool_version(t) for t in ("hadolint", "trivy")})
        froms = parse_from_lines(dockerfile)
        hits = [
            *dockerfile_rules(dockerfile),
            *parse_hadolint(jail(files["hadolint"])),
            *parse_trivy_config(jail(files["trivy-config"]), self.root),
        ]
        self.config_hits["dockerfile"] = hits
        self.stages["scan_dockerfile"] = f"{len(hits)} rule hits"
        return {
            "dockerfile": True,
            "base_images": [{"line": f.line, "ref": f.ref, "digest_pinned": f.digest_pinned}
                            for f in froms],
            "hit_counts": dict(Counter(f"{h.tool}:{h.rule}" for h in hits)),
            "top_hits": self._brief(hits),
        }  # fmt: skip

    def scan_workflows(self) -> dict:
        with self._stage("workflows"):
            return self._scan_workflows()

    def _scan_workflows(self) -> dict:
        if not has_workflows(self.root):
            self.config_hits["workflows"] = []
            self.stages["scan_workflows"] = "no workflows"
            return {"workflows": False, "note": "the target has no CI workflows"}
        files = run_workflow_tools(self.root, self.out)
        self.outputs.update(files)
        self.versions["zizmor"] = tool_version("zizmor")
        wf_dir = self.root / ".github" / "workflows"
        wf_files = sorted(p for p in wf_dir.iterdir() if p.suffix in {".yml", ".yaml"})
        hits = [
            *(h for w in wf_files for h in workflow_rules(w)),
            *parse_zizmor(jail(files["zizmor"])),
        ]
        self.config_hits["workflows"] = hits
        self.stages["scan_workflows"] = f"{len(hits)} rule hits"
        return {
            "workflows": [workspace_relative(w) for w in wf_files],
            "hit_counts": dict(Counter(f"{h.tool}:{h.rule}" for h in hits)),
            "top_hits": self._brief(hits),
        }

    def scan_image(self) -> dict:
        with self._stage("image"):
            return self._scan_image()

    def _scan_image(self) -> dict:
        """Scan the Dockerfile's final base image, if its digest-verified layout is cached."""
        dockerfile = self.root / "Dockerfile"
        froms = parse_from_lines(dockerfile) if dockerfile.is_file() else []
        if not froms:
            raise StageError("the target has no Dockerfile FROM line, so there is no image")
        ref = froms[-1].ref
        image = load_image(ref)
        if image is None:
            self.stages["scan_image"] = "image not cached"
            return {
                "scanned": False,
                "reason": f"base image {ref!r} is not in the local image cache "
                "(targets/images.json). Fetching an image needs network access and "
                "scripts/fetch_image.py, which this agent cannot run.",
            }
        files = run_image_tools(image, self.out)
        self.outputs.update(files)
        self.versions.update({t: tool_version(t) for t in ("trivy", "grype")})
        rel_dockerfile = workspace_relative(dockerfile)
        eosl = eosl_hit(self.outputs, rel_dockerfile, froms[-1])
        self.config_hits["image"] = [eosl] if eosl else []
        self.image_ctx = (image, froms[-1])
        raw = [*parse_trivy(jail(files["trivy-image"])), *parse_grype(jail(files["grype-image"]))]
        exact = [m for m in raw if m.match_types != frozenset({"cpe-match"})]
        self.stages["scan_image"] = f"{len(exact)} package matches"
        return {
            "scanned": True,
            "image": image["image"],
            "manifest_digest": image["manifest_digest"],
            "matches": len(exact),
            "cpe_only_excluded": len(raw) - len(exact),
            "by_severity": dict(Counter(m.severity.value for m in exact)),
            "end_of_life_os": eosl is not None,
        }

    # -- package forensics ------------------------------------------------------------------
    def anomaly_rules(self) -> dict:
        with self._stage("anomaly"):
            return self._anomaly_rules()

    def _anomaly_rules(self) -> dict:
        """Typosquat, install-script, lockfile and unexpected-dependency rules."""
        lock = parse_lockfile(self.lockfile, workspace_relative(self.lockfile))
        hits = single_commit_rules(lock, TopList.load())
        if self.target.get("base_target"):
            base = load_target(self.target["base_target"])
            base_lockfile = jail(Path(base["path"]) / base["lockfile"])
            base_lock = parse_lockfile(base_lockfile, workspace_relative(base_lockfile))
            hits += diff_rules(base_lock, lock, self.graph())
        self.anomalies, self.anomalies_done = hits, True
        self.stages["anomaly_rules"] = f"{len(hits)} rule hits"
        return {
            "hit_counts": dict(Counter(h.rule for h in hits)),
            "hits": [{"rule": h.rule, "package": h.node, "severity": h.severity.value,
                      "message": h.message[:200]} for h in hits[:TOP_HITS * 2]],
            "compared_against": self.target.get("base_target"),
        }  # fmt: skip

    # -- assembly ---------------------------------------------------------------------------
    def coverage(self) -> dict:
        ran = [s for s in bl.SCANNERS if s in self.outputs]
        return {
            "scanners_run": ran,
            "scanners_not_run": [s for s in bl.SCANNERS if s not in ran],
            "dockerfile_scanned": "dockerfile" in self.config_hits,
            "workflows_scanned": "workflows" in self.config_hits,
            "image_scanned": self.image_ctx is not None,
            "anomaly_rules_run": self.anomalies_done,
            "stages": dict(self.stages),
        }

    def build_findings(self) -> dict:
        with self._stage("build"):
            return self._build_findings()

    def _build_findings(self) -> dict:
        """Correlate every raw result produced so far into scored, stored findings."""
        if self.sbom_summary is None:
            raise StageError("generate_sbom must run first: findings are placed on the graph")
        outputs, versions = dict(self.outputs), dict(self.versions)
        config_hits = {k: list(v) for k, v in dict(self.config_hits).items()}
        anomalies = list(self.anomalies)
        cov = self.coverage()
        if not (cov["scanners_run"] or config_hits or self.anomalies_done):
            raise StageError(
                "nothing has been scanned yet. Run at least one scanner or inspection first; "
                "no output is not the same as no findings."
            )
        graph = self.graph()
        raw = []
        for scanner in cov["scanners_run"]:
            raw += PARSERS[scanner](jail(outputs[scanner]))
        groups = correlate(raw)
        hits = [h for stage in config_hits.values() for h in stage]
        image_raw = []
        if self.image_ctx is not None:
            image_raw = [
                *parse_trivy(jail(outputs["trivy-image"])),
                *parse_grype(jail(outputs["grype-image"])),
            ]
        wanted = {c for g in groups for c in g.cves} | {
            i for m in image_raw for i in m.ids if i.startswith("CVE-")
        }
        epss = load_epss(bl.CACHE / "feeds" / "epss_scores-current.csv.gz", wanted)
        kev = load_kev(bl.CACHE / "feeds" / "known_exploited_vulnerabilities.json")

        store = EvidenceStore()
        lock_rel = workspace_relative(self.lockfile)
        drafts, unmapped = bl.vuln_drafts(
            store, groups, graph, lock_rel, outputs, versions, epss, kev
        )
        drafts += config_drafts(store, hits, outputs, versions)
        drafts += anomaly_drafts(store, anomalies, graph)
        if self.image_ctx is not None:
            image, from_line = self.image_ctx
            part, self.image_stats = image_drafts(
                store, image, from_line, workspace_relative(self.root / "Dockerfile"),
                outputs, versions, epss, kev,
            )  # fmt: skip
            drafts += part

        dockerfile = self.root / "Dockerfile"
        app = scan_app(self.root, dockerfile if dockerfile.exists() else None)
        resolve_top_level(app, parse_lockfile(self.lockfile, lock_rel))
        drafts = enrich(store, drafts, app)
        fs = assemble(store, drafts)
        (self.out / "findings.json").write_text(fs.model_dump_json(indent=1))

        f = fs.findings
        deps = [x for x in f if x.type in bl.DEPENDENCY_TYPES]
        tool_count = Counter(len(g.tools) for g in groups)
        summary = {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "target": self.sbom_summary["target"],
            "tools": versions,
            "databases": bl.db_metadata(outputs.get("grype")),
            "outputs": outputs,
            "raw_matches": dict(Counter(m.tool for m in raw)),
            "groups": len(groups),
            "groups_by_tool_count": {f"{k}_tools": v for k, v in sorted(tool_count.items())},
            "findings": len(f),
            "evidence_records": len(fs.evidence),
            "unmapped": unmapped,
            "by_type": dict(Counter(x.type.value for x in f)),
            "by_severity": dict(Counter(x.severity.value for x in f)),
            "dependency_findings": len(deps),
            "runtime_findings": sum(
                1 for x in deps if x.factors.exposure is not Exposure.BUILD_OR_DEV
            ),
            "dev_only_findings": sum(
                1 for x in deps if x.factors.exposure is Exposure.BUILD_OR_DEV
            ),
            "kev_findings": sum(1 for x in f if x.factors.kev),
            "with_fix": sum(1 for x in f if x.fixed_in),
            "vulnerable_packages": len({x.component.purl for x in deps}),
            "image": self.image_stats,
            "posture_hits": dict(Counter(f"{h.tool}:{h.rule}" for h in hits)),
            "anomaly_hits": dict(Counter(h.rule for h in anomalies)),
            "base_target": self.target.get("base_target"),
            "synthetic": bool(self.target.get("synthetic")),
            "by_risk_level": dict(Counter(x.risk.level.value for x in f if x.risk)),
            "by_reachability": dict(Counter(x.factors.reachability.value for x in f)),
            "by_exposure": dict(Counter(x.factors.exposure.value for x in f)),
            "coverage": cov,
            "app_context": {
                "runtime_imports": sorted(app.runtime_imports),
                "dev_imports": sorted(app.dev_imports),
                "network_facts": [f"{s.file}:{s.line}" for s in app.network_facts],
                "dynamic_requires": app.dynamic_requires,
            },
        }  # fmt: skip
        if self.db is not None:
            summary["store"] = {"db": workspace_relative(jail(self.db)), "run_id": self.run_id}
        (self.out / "baseline.json").write_text(json.dumps(summary, indent=2))
        (self.out / "baseline.md").write_text(bl.render_markdown(summary, fs))
        if self.db is not None:
            conn = connect(self.db)
            try:
                save_run(conn, self.run_id, summary, fs, graph)
            finally:
                conn.close()
        return summary
