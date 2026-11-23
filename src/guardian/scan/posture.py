"""D1.S5: container image and CI/CD inspection.

* Image: Trivy and Grype scan the base image as an OCI layout, offline. The layout is fetched
  and digest-verified by scripts/fetch_image.py. Grype CPE-only matches are excluded (D5-03).
* Dockerfile: Hadolint and Trivy misconfiguration checks, plus guardian rules for digest
  pinning, latest/missing tags and root user.
* Workflows: zizmor (offline), plus guardian rules for SHA pinning and risky triggers.

The target repository is untrusted. zizmor runs with ``--no-config`` and Hadolint with
``--disable-ignore-pragma``, so the repo cannot suppress findings about itself.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from guardian import __version__
from guardian.scan.common import (
    Draft,
    EvidenceStore,
    excerpt,
    exploit_refs,
    fixed_by_tool,
    pointer_excerpt,
    ref_of,
    sort_key,
)
from guardian.scan.parsers import SEVERITY_RANK, correlate, norm_severity, parse_grype, parse_trivy
from guardian.schemas.common import Ecosystem
from guardian.schemas.evidence import EvidenceKind, EvidenceRef
from guardian.schemas.finding import FindingType, Severity
from guardian.schemas.risk import Exposure, RiskFactors
from guardian.schemas.sbom import Component
from guardian.tools.runner import WORKSPACE, jail, run_tool, workspace_relative

CACHE = WORKSPACE / "cache"
IMAGES_FILE = WORKSPACE / "targets" / "images.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)""")
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
USER = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE)

# Guardian rule metadata. Severities here are our documented rule choices (DECISIONS D5-02).
RULES = {
    "GR-IMG-001": (Severity.MEDIUM, FindingType.UNTRUSTED_IMAGE,
                   "base image is not pinned by digest"),
    "GR-IMG-002": (Severity.HIGH, FindingType.UNTRUSTED_IMAGE,
                   "base image uses the 'latest' tag or no tag"),
    "GR-IMG-003": (Severity.MEDIUM, FindingType.MISCONFIGURATION,
                   "final stage runs as root (no non-root USER)"),
    "GR-CI-001": (Severity.HIGH, FindingType.UNPINNED_CI,
                  "action is referenced by tag or branch, not a full commit SHA"),
    "GR-CI-002": (Severity.HIGH, FindingType.UNPINNED_CI,
                  "pull_request_target trigger combined with actions/checkout"),
    "GR-CI-003": (Severity.MEDIUM, FindingType.UNPINNED_CI,
                  "docker:// action image is not pinned by digest"),
}  # fmt: skip

# Rules from different tools that describe the same problem at the same line merge (D5-01).
CONCERN = {
    ("zizmor", "unpinned-uses"): "action-not-sha-pinned",
    ("guardian-rules", "GR-CI-001"): "action-not-sha-pinned",
}
HADOLINT_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.LOW,
                  "style": Severity.LOW}  # fmt: skip


@dataclass(frozen=True)
class ConfigHit:
    tool: str
    rule: str
    severity: Severity
    ftype: FindingType
    file: str  # workspace-relative
    line: int | None
    message: str
    pointer: str | None = None  # JSON pointer into tool output (None for guardian rules)
    line_text: str | None = None  # exact stripped source line (guardian rules)
    output: str | None = None  # key in the run's outputs map for the pointer

    @property
    def concern(self) -> str:
        return CONCERN.get((self.tool, self.rule), f"{self.tool}:{self.rule}")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _hit(rule: str, file: str, line: int, text: str) -> ConfigHit:
    severity, ftype, message = RULES[rule]
    return ConfigHit("guardian-rules", rule, severity, ftype, file, line, message,
                     line_text=text.strip())  # fmt: skip


# --- Dockerfile ----------------------------------------------------------------------------


@dataclass(frozen=True)
class FromLine:
    line: int
    text: str
    ref: str
    alias: str | None

    @property
    def digest_pinned(self) -> bool:
        return "@sha256:" in self.ref

    @property
    def tag(self) -> str | None:
        name = self.ref.split("@", 1)[0]
        last = name.rsplit("/", 1)[-1]
        return last.split(":", 1)[1] if ":" in last else None


def parse_from_lines(path: Path) -> list[FromLine]:
    out = []
    for number, text in enumerate(_lines(path), start=1):
        m = FROM.match(text)
        if m:
            out.append(FromLine(number, text, m.group(1), m.group(2)))
    return out


def dockerfile_rules(path: Path) -> list[ConfigHit]:
    rel = workspace_relative(path)
    lines = _lines(path)
    froms = parse_from_lines(path)
    hits: list[ConfigHit] = []
    aliases: set[str] = set()
    for f in froms:
        is_stage_ref = f.ref.lower() in aliases or f.ref == "scratch"
        if f.alias:
            aliases.add(f.alias.lower())
        if is_stage_ref:
            continue
        if not f.digest_pinned:
            hits.append(_hit("GR-IMG-001", rel, f.line, f.text))
        if not f.digest_pinned and f.tag in (None, "latest"):
            hits.append(_hit("GR-IMG-002", rel, f.line, f.text))
    if froms:
        final = froms[-1]
        users = [(n, t, m.group(1)) for n, t in enumerate(lines, start=1)
                 if n > final.line and (m := USER.match(t))]  # fmt: skip
        if not users or users[-1][2] in {"root", "0", "0:0", "root:root"}:
            where = users[-1] if users else (final.line, final.text, None)
            hits.append(_hit("GR-IMG-003", rel, where[0], where[1]))
    return hits


# --- workflows -----------------------------------------------------------------------------


def workflow_rules(path: Path) -> list[ConfigHit]:
    """Line-based rules. zizmor, a real YAML parser, cross-checks GR-CI-001."""
    rel = workspace_relative(path)
    lines = _lines(path)
    hits: list[ConfigHit] = []
    checkout_lines = []
    for number, text in enumerate(lines, start=1):
        if text.lstrip().startswith("#"):
            continue
        m = USES.match(text)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./"):
            continue  # local action, versioned with the repo
        if ref.startswith("docker://"):
            if "@sha256:" not in ref:
                hits.append(_hit("GR-CI-003", rel, number, text))
            continue
        _, _, version = ref.partition("@")
        if not SHA40.match(version):
            hits.append(_hit("GR-CI-001", rel, number, text))
        if ref.split("@", 1)[0] == "actions/checkout":
            checkout_lines.append((number, text))
    trigger = next(
        ((n, t) for n, t in enumerate(lines, start=1)
         if re.search(r"\bpull_request_target\b", t.split("#", 1)[0])),
        None,
    )  # fmt: skip
    if trigger and checkout_lines:
        hits.append(_hit("GR-CI-002", rel, trigger[0], trigger[1]))
    return hits


# --- tool output parsers -------------------------------------------------------------------


def parse_hadolint(path: Path) -> list[ConfigHit]:
    out = []
    for i, r in enumerate(json.loads(path.read_text() or "[]")):
        out.append(ConfigHit("hadolint", r["code"], HADOLINT_LEVEL.get(r.get("level"),
                             Severity.UNKNOWN), FindingType.MISCONFIGURATION,
                             workspace_relative(r["file"]), r.get("line"), r.get("message", ""),
                             pointer=f"/{i}", output="hadolint"))  # fmt: skip
    return out


def parse_trivy_config(path: Path, target_root: Path) -> list[ConfigHit]:
    out = []
    for ri, result in enumerate(json.loads(path.read_text()).get("Results") or []):
        file = workspace_relative(target_root / result["Target"])
        for mi, m in enumerate(result.get("Misconfigurations") or []):
            line = (m.get("CauseMetadata") or {}).get("StartLine") or None
            out.append(ConfigHit("trivy", m["ID"], norm_severity(m.get("Severity")),
                                 FindingType.MISCONFIGURATION, file, line,
                                 m.get("Title") or m.get("Message", ""),
                                 pointer=f"/Results/{ri}/Misconfigurations/{mi}",
                                 output="trivy-config"))  # fmt: skip
    return out


def zizmor_primary(finding: dict) -> dict:
    locs = finding["locations"]
    return next((loc for loc in locs if loc["symbolic"].get("kind") == "Primary"), locs[0])


def parse_zizmor(path: Path) -> list[ConfigHit]:
    out = []
    for i, f in enumerate(json.loads(path.read_text() or "[]")):
        if f.get("ignored"):
            continue
        loc = zizmor_primary(f)
        key = loc["symbolic"]["key"].get("Local", {})
        file = key.get("given_path") or key.get("verbatim_path")
        sev = f["determinations"]["severity"]
        severity = Severity.LOW if sev == "Informational" else norm_severity(sev)
        out.append(ConfigHit("zizmor", f["ident"], severity, FindingType.UNPINNED_CI,
                             workspace_relative(file),
                             loc["concrete"]["location"]["start_point"]["row"] + 1,
                             f.get("desc", ""), pointer=f"/{i}", output="zizmor"))  # fmt: skip
    return out


# --- running the tools ---------------------------------------------------------------------


def load_image(ref: str) -> dict | None:
    """Image record from targets/images.json matching a Dockerfile FROM reference."""
    if not IMAGES_FILE.exists():
        return None
    name = ref.split("@", 1)[0]
    full = name if name.count("/") >= 2 else (
        f"docker.io/library/{name}" if "/" not in name else f"docker.io/{name}"
    )  # fmt: skip
    return next((i for i in json.loads(IMAGES_FILE.read_text())["images"] if i["image"] == full),
                None)  # fmt: skip


def run_posture_tools(target_root: Path, out: Path, image: dict | None) -> dict[str, str]:
    files = {
        "hadolint": out / "hadolint.json",
        "trivy-config": out / "trivy-config.json",
        "zizmor": out / "zizmor.json",
    }
    dockerfile = target_root / "Dockerfile"
    if dockerfile.is_file():
        run = run_tool("hadolint", ["--format", "json", "--disable-ignore-pragma",
                                    str(jail(dockerfile))], offline=True,
                       ok_codes=frozenset({0, 1}))  # fmt: skip
        files["hadolint"].write_bytes(run.stdout)
    else:
        files["hadolint"].write_text("[]")  # no Dockerfile: nothing to lint
    run_tool("trivy", ["config", "--skip-check-update", "--cache-dir", str(CACHE / "trivy"),
                       "--quiet", "-f", "json", "-o", str(jail(files["trivy-config"])),
                       str(jail(target_root))], offline=True)  # fmt: skip
    workflows = target_root / ".github" / "workflows"
    has_workflows = workflows.is_dir() and any(
        p.is_file() and p.suffix in {".yml", ".yaml"} for p in workflows.iterdir()
    )
    if has_workflows:
        run = run_tool("zizmor", ["--offline", "--no-config", "--format", "json",
                                  str(jail(target_root))], offline=True,
                       ok_codes=frozenset({0, *range(10, 15)}))  # fmt: skip
        files["zizmor"].write_bytes(run.stdout)
    else:
        files["zizmor"].write_text("[]")  # no workflows: nothing to analyse

    if image is not None:
        layout = jail(image["oci_layout"])
        files["trivy-image"] = out / "trivy-image.json"
        files["grype-image"] = out / "grype-image.json"
        run_tool("trivy", ["image", "--input", str(layout), "--skip-db-update",
                           "--skip-java-db-update", "--offline-scan", "--cache-dir",
                           str(CACHE / "trivy"), "--scanners", "vuln", "--quiet", "-f", "json",
                           "-o", str(jail(files["trivy-image"]))], offline=True)  # fmt: skip
        run_tool("grype", [f"oci-dir:{layout}", "-q", "-o", "json", "--file",
                           str(jail(files["grype-image"]))],
                 env={"GRYPE_DB_CACHE_DIR": str(CACHE / "grype"), "GRYPE_DB_AUTO_UPDATE": "false"},
                 offline=True)  # fmt: skip
    return {k: workspace_relative(v) for k, v in files.items()}


# --- drafts --------------------------------------------------------------------------------


def _component_for(hit_file: str, line_text: str | None) -> Component:
    text = line_text or ""
    m = USES.match(text)
    if m and not m.group(1).startswith(("./", "docker://")):
        name, _, version = m.group(1).partition("@")
        purl = f"pkg:github/{name}@{version}" if version else f"pkg:github/{name}"
        return Component(name=name, version=version or None, purl=purl,
                         ecosystem=Ecosystem.GITHUB_ACTIONS)  # fmt: skip
    f = FROM.match(text)
    if f:
        return image_component(f.group(1))
    eco = Ecosystem.GITHUB_ACTIONS if "/.github/workflows/" in f"/{hit_file}" else Ecosystem.OCI
    return Component(name=hit_file, ecosystem=eco)


def image_component(ref: str) -> Component:
    name = ref.split("@", 1)[0]
    repo, _, tag = name.rpartition(":") if ":" in name.rsplit("/", 1)[-1] else (name, "", "")
    path = repo if "/" in repo else f"library/{repo}"
    return Component(name=repo, version=tag or None,
                     purl=f"pkg:docker/{path}@{tag}" if tag else f"pkg:docker/{path}",
                     ecosystem=Ecosystem.OCI)  # fmt: skip


def config_drafts(store: EvidenceStore, hits: list[ConfigHit], outputs: dict[str, str],
                  versions: dict[str, str]) -> list[Draft]:  # fmt: skip
    grouped: dict[tuple, list[ConfigHit]] = defaultdict(list)
    for h in hits:
        grouped[(h.file, h.line, h.concern)].append(h)

    drafts = []
    for (file, line, _), group in sorted(grouped.items(), key=lambda kv: (kv[0][0],
                                         kv[0][1] or 0, kv[0][2])):  # fmt: skip
        refs: list[EvidenceRef] = []
        for h in sorted(group, key=lambda x: (x.tool, x.rule)):
            if h.pointer is None:
                rec = store.add(("rule", h.rule, h.file, h.line),
                                kind=EvidenceKind.FILE_LOCATION, tool=h.tool,
                                tool_version=f"guardian {__version__}", ref=h.rule,
                                file=h.file, line=h.line, excerpt=h.line_text)  # fmt: skip
            else:
                key = h.output or h.tool
                rec = store.add(
                    ("cfg", key, h.pointer),
                    kind=EvidenceKind.SCANNER_RESULT,
                    tool=h.tool,
                    tool_version=versions.get(h.tool),
                    ref=h.rule,
                    file=h.file,
                    line=h.line,
                    excerpt=pointer_excerpt(outputs[key], h.pointer, h.message),
                )
            refs.append(ref_of(rec))
        top = max(group, key=lambda x: SEVERITY_RANK[x.severity])
        text = next((h.line_text for h in group if h.line_text), None)
        if text is None and line is not None:
            text = _lines(jail(file))[line - 1].strip()
        component = _component_for(file, text)
        ftype = next((h.ftype for h in group if h.tool == "guardian-rules"), top.ftype)
        label = f"{component.name}@{component.version}" if component.version else component.name
        draft = {
            "type": ftype,
            "title": excerpt(f"{label}: {top.message}", 200),
            "component": component,
            "advisory_ids": tuple(sorted({h.rule for h in group})),
            "severity": top.severity,
            "evidence": tuple(refs),
        }
        drafts.append((sort_key(False, False, top.severity, None, f"{file}:{line or 0}",
                                ",".join(sorted({h.rule for h in group}))), draft))  # fmt: skip
    return drafts


def image_drafts(store: EvidenceStore, image: dict, from_line: FromLine, dockerfile: str,
                 outputs: dict[str, str], versions: dict[str, str], epss, kev
                 ) -> tuple[list[Draft], dict]:  # fmt: skip
    trivy_raw = parse_trivy(jail(outputs["trivy-image"]))
    grype_all = parse_grype(jail(outputs["grype-image"]))
    grype_raw = [m for m in grype_all if m.match_types != frozenset({"cpe-match"})]
    groups = correlate([*trivy_raw, *grype_raw])
    image_label = f"{image['image']}@{image['manifest_digest']}"
    base = image_component(from_line.ref)

    layout_rec = store.add(
        ("oci", image["manifest_digest"]), kind=EvidenceKind.FILE_LOCATION, tool="oci-layout",
        ref=image["manifest_digest"], file=f"{image['oci_layout']}/index.json",
        excerpt=f"{image['image']} {image['platform']} manifest {image['manifest_digest']}",
    )  # fmt: skip
    drafts = []
    for group in groups:
        refs = [ref_of(layout_rec)]
        for m in sorted(group.matches, key=lambda x: (x.tool, x.advisory_id, x.pointer)):
            key = f"{m.tool}-image"
            rec = store.add(
                ("img", key, m.pointer),
                kind=EvidenceKind.SCANNER_RESULT,
                tool=m.tool,
                tool_version=versions.get(m.tool),
                ref=m.advisory_id,
                file=dockerfile,
                line=from_line.line,
                excerpt=pointer_excerpt(outputs[key], m.pointer, m.summary),
            )
            refs.append(ref_of(rec))
        exploit, epss_value, kev_flag, in_kev = exploit_refs(store, group, epss, kev)
        refs.extend(exploit)
        purl = next((m.purl for m in group.matches if m.purl), None)
        eco = {"apk": Ecosystem.APK, "npm": Ecosystem.NPM}.get(
            (purl or "pkg:other/").split(":", 1)[1].split("/", 1)[0], Ecosystem.OTHER
        )
        label = f"{group.name}@{group.version}"
        summary = next((m.summary for m in group.matches if m.summary), sorted(group.ids)[0])
        draft = {
            "type": FindingType.VULNERABLE_IMAGE_PACKAGE,
            "title": excerpt(f"{label} in {base.name}:{base.version}: {summary}", 200),
            "component": Component(name=group.name, version=group.version, purl=purl,
                                   ecosystem=eco),
            "dependency_path": (image_label, label),
            "introduced_by": (image_label,),
            "advisory_ids": tuple(sorted(group.ids)),
            "severity": group.severity,
            "fixed_in": fixed_by_tool(group),
            "evidence": tuple(refs),
            "factors": RiskFactors(cvss=group.cvss, epss=epss_value, kev=kev_flag,
                                   exposure=Exposure.UNKNOWN),
        }  # fmt: skip
        drafts.append((sort_key(False, in_kev, group.severity, group.cvss, label, group), draft))
    stats = {
        "image": image["image"], "manifest_digest": image["manifest_digest"],
        "trivy_matches": len(trivy_raw), "grype_matches": len(grype_all),
        "grype_cpe_only_excluded": len(grype_all) - len(grype_raw), "groups": len(groups),
        "groups_by_tool_count": {f"{k}_tools": v for k, v in sorted(
            Counter(len(g.tools) for g in groups).items())},
    }  # fmt: skip
    return drafts, stats


def eosl_hit(outputs: dict[str, str], dockerfile: str, from_line: FromLine) -> ConfigHit | None:
    """Trivy's own end-of-service-life flag for the image OS (not our judgement)."""
    os_info = json.loads(jail(outputs["trivy-image"]).read_text()).get("Metadata", {}).get("OS")
    if not os_info or os_info.get("EOSL") is not True:
        return None
    return ConfigHit("trivy", "EOSL", Severity.HIGH, FindingType.UNTRUSTED_IMAGE, dockerfile,
                     from_line.line, f"base image OS {os_info['Family']} {os_info['Name']} is "
                     "end-of-service-life (no more security updates)",
                     pointer="/Metadata/OS", output="trivy-image")  # fmt: skip
