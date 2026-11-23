"""D1.S3 pipeline: discover files, generate the SBOM, build the graph, cross-check, summarize."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from guardian.sbom.cyclonedx import cross_check, load_bom
from guardian.sbom.npm_lock import build_graph, parse_lockfile
from guardian.schemas.graph import EdgeKind
from guardian.schemas.sbom import DependencyScope
from guardian.targets import DYNAMIC_TARGETS_FILE
from guardian.tools.runner import WORKSPACE, jail, run_tool, tool_version, workspace_relative

TARGETS_FILE = WORKSPACE / "targets" / "targets.json"
SKIP_DIRS = {".git", "node_modules"}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "poetry.lock", "Pipfile.lock", "pom.xml", "build.gradle", "go.mod",
    "go.sum", "Cargo.lock",
}  # fmt: skip


class TargetError(ValueError):
    pass


def load_target(name: str) -> dict:
    targets = {t["name"]: t for t in json.loads(TARGETS_FILE.read_text())["targets"]}
    if DYNAMIC_TARGETS_FILE.exists():
        dynamic = json.loads(DYNAMIC_TARGETS_FILE.read_text()).get("targets", [])
        targets.update({t["name"]: t for t in dynamic})
    if name not in targets:
        raise TargetError(f"unknown target {name!r}; registered: {sorted(targets)}")
    target = targets[name]
    if target.get("dynamic"):
        # The commit was resolved and recorded when the repository was cloned; Git metadata is
        # removed afterwards, so there is no .git/HEAD to compare against.
        if not jail(target["path"]).is_dir():
            raise TargetError(f"{name}: dynamic target directory is missing")
        return target
    root = jail(target["path"])
    head = (root / ".git" / "HEAD").read_text().strip()
    if head != target["commit"]:
        raise TargetError(f"{name}: checkout is at {head!r}, pinned commit is {target['commit']}")
    return target


def discover(root: Path) -> dict[str, list[str]]:
    """Discovery-agent file search: manifests, lockfiles, Dockerfiles, compose files, CI."""
    found: dict[str, list[str]] = {"manifests": [], "dockerfiles": [], "compose": [], "ci": []}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts) or not path.is_file():
            continue
        name = path.name
        ws = workspace_relative(path)
        if name in MANIFEST_NAMES:
            found["manifests"].append(ws)
        elif name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            found["dockerfiles"].append(ws)
        elif name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            found["compose"].append(ws)
        elif rel.parts[:2] == (".github", "workflows") and path.suffix in {".yml", ".yaml"}:
            found["ci"].append(ws)
    return found


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_sbom(target_root: Path, out_file: Path) -> None:
    run_tool(
        "syft",
        ["scan", f"dir:{jail(target_root)}", "-q", "-o", f"cyclonedx-json@1.5={jail(out_file)}"],
        timeout_s=600,
    )


def build(target_name: str, out_dir: str | Path) -> dict:
    target = load_target(target_name)
    root = jail(target["path"])
    out = jail(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    files = discover(root)

    sbom_file = out / "sbom.cdx.json"
    generate_sbom(root, sbom_file)
    bom = load_bom(sbom_file)

    lock_path = jail(Path(target["path"]) / target["lockfile"])
    lock = parse_lockfile(lock_path, workspace_relative(lock_path))
    graph, unresolved = build_graph(lock)
    (out / "graph.json").write_text(graph.model_dump_json(indent=1))

    check = cross_check(graph, bom)
    depths = graph.depths()
    runtime = [n for n in graph.nodes if n.scope is DependencyScope.RUNTIME and n.bom_ref != "."]
    dev = [n for n in graph.nodes if n.scope is DependencyScope.DEV]
    direct = [n for n in graph.nodes if n.direct]
    unreachable = [n.bom_ref for n in graph.nodes if n.bom_ref not in depths]
    required_unresolved = [u for u in unresolved if u.kind is not EdgeKind.OPTIONAL_DEPENDS_ON]

    summary = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "target": {k: target[k] for k in ("name", "repo", "commit", "license", "path")},
        "tools": {"syft": tool_version("syft")},
        "artifacts": {
            "sbom": {"file": workspace_relative(sbom_file), "sha256": sha256_file(sbom_file),
                     "format": f"CycloneDX {bom.spec_version} JSON"},
            "graph": {"file": workspace_relative(out / "graph.json")},
        },
        "discovered_files": files,
        "sbom": {
            "components": len(bom.components),
            "by_purl_type": dict(Counter((c.purl or "none").split("/")[0]
                                         for c in bom.components)),
            "ci_actions": sorted({c.purl for c in bom.by_purl_type("github") if c.purl}),
            "dependency_records": len(bom.dependencies),
        },
        "graph": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "runtime_install_paths": len(runtime),
            "dev_install_paths": len(dev),
            "unique_runtime_packages": len({graph.label(n.bom_ref) for n in runtime}),
            "unique_dev_packages": len({graph.label(n.bom_ref) for n in dev}),
            "direct": {"runtime": sorted(graph.label(n.bom_ref) for n in direct
                                         if n.scope is DependencyScope.RUNTIME),
                       "dev": sorted(graph.label(n.bom_ref) for n in direct
                                     if n.scope is DependencyScope.DEV)},
            "by_depth": dict(sorted(Counter(depths.values()).items())),
            "max_depth": max(depths.values()),
            "unreachable_from_root": unreachable,
            "unresolved_optional": len(unresolved) - len(required_unresolved),
            "unresolved_required": [f"{u.source} -> {u.name}" for u in required_unresolved],
        },
        "cross_check_vs_sbom": {
            "agrees": check.agrees,
            "graph_runtime_unique": check.graph_runtime,
            "sbom_npm_unique": check.sbom_npm,
            "only_in_graph": list(check.only_in_graph),
            "only_in_sbom": list(check.only_in_sbom),
        },
    }  # fmt: skip
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary
