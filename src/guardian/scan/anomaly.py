"""D1.S6: supply-chain anomaly rules (PDF section 6, "Suspicious-change detection").

Every rule is deterministic, and every finding cites exact lockfile or manifest lines,
popular-list ranks and registry metadata that the verifier rechecks.

* GR-TYPO-001  name within edit distance of a top-5,000 package, and not itself high-impact
* GR-INST-001  lockfile marks hasInstallScript (script not inspectable: package not installed)
* GR-INST-002  lifecycle script with network/obfuscation commands (manifest available)
* GR-LOCK-001  resolved from a host other than registry.npmjs.org
* GR-LOCK-002  registry tarball URL does not match name@version
* GR-LOCK-004  integrity changed with no version change (vs base commit)
* GR-LOCK-005  resolved URL changed with no version change (vs base commit)
* GR-DEP-001   new transitive package from a minor/patch bump of a direct dependency
* GR-DEP-002   new transitive package with no direct-dependency change at all
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlparse

from guardian import __version__
from guardian.sbom.npm_lock import ROOT_ID, NpmLock
from guardian.scan.common import Draft, EvidenceStore, excerpt, ref_of, sort_key
from guardian.scan.parsers import SEVERITY_RANK
from guardian.schemas.evidence import EvidenceKind, EvidenceRef
from guardian.schemas.finding import FindingType, Severity
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.risk import Exposure, RiskFactors
from guardian.schemas.sbom import DependencyScope
from guardian.tools.runner import WORKSPACE, jail

TOPLIST = WORKSPACE / "cache" / "toplists" / "npm-high-impact-1.13.0.json"
MOCK_REGISTRY = WORKSPACE / "targets" / "mock-registry" / "registry.json"
ALLOWED_HOSTS = frozenset({"registry.npmjs.org"})
TOP_N = 5000  # PDF: "against the top 5,000 packages per ecosystem"
LIFECYCLE = ("preinstall", "install", "postinstall")
SUSPICIOUS = re.compile(r"\b(curl|wget|base64|eval|nc|powershell)\b|https?://|/dev/tcp")
RECENT_DAYS, LOW_DOWNLOADS = 90, 1000

RULES = {
    "GR-TYPO-001": (Severity.MEDIUM, FindingType.TYPOSQUAT),
    "GR-INST-001": (Severity.LOW, FindingType.INSTALL_SCRIPT),
    "GR-INST-002": (Severity.HIGH, FindingType.INSTALL_SCRIPT),
    "GR-LOCK-001": (Severity.HIGH, FindingType.LOCKFILE_CHANGE),
    "GR-LOCK-002": (Severity.MEDIUM, FindingType.LOCKFILE_CHANGE),
    "GR-LOCK-004": (Severity.HIGH, FindingType.LOCKFILE_CHANGE),
    "GR-LOCK-005": (Severity.MEDIUM, FindingType.LOCKFILE_CHANGE),
    "GR-DEP-001": (Severity.MEDIUM, FindingType.UNEXPECTED_DEPENDENCY),
    "GR-DEP-002": (Severity.HIGH, FindingType.UNEXPECTED_DEPENDENCY),
}


# --- edit distance ---------------------------------------------------------------------------

QWERTY = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
_POS = {ch: (r, c) for r, row in enumerate(QWERTY) for c, ch in enumerate(row)}


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: insert, delete, substitute and adjacent transpose."""
    if a == b:
        return 0
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (
                prev2 is not None
                and i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


# Check whether two characters are adjacent on a QWERTY keyboard.
def keyboard_adjacent(x: str, y: str) -> bool:
    if x not in _POS or y not in _POS:
        return False
    (r1, c1), (r2, c2) = _POS[x], _POS[y]
    return abs(r1 - r2) <= 1 and abs(c1 - c2) <= 1 and (x != y)


# Identify the type of change between two package names.
def classify(candidate: str, popular: str) -> str:
    """Name the single edit (for distance 1) or 'multiple edits'."""
    if osa_distance(candidate, popular) > 1:
        return "multiple edits"
    if re.sub(r"[-_.]", "", candidate) == re.sub(r"[-_.]", "", popular):
        return "separator change"
    if len(candidate) == len(popular):
        diff = [i for i, (p, q) in enumerate(zip(candidate, popular, strict=True)) if p != q]
        if len(diff) == 1:
            i = diff[0]
            return (
                "keyboard-adjacent substitution"
                if keyboard_adjacent(candidate[i], popular[i])
                else "substitution"
            )
        if len(diff) == 2 and diff[1] == diff[0] + 1:
            return "transposition"
    if len(candidate) == len(popular) + 1:
        return "insertion"
    if len(candidate) == len(popular) - 1:
        return "deletion"
    return "multiple edits"


def max_distance(name: str) -> int:
    """PDF: distance 2. Short names get 1, otherwise nearly every short name collides."""
    return 1 if len(name) <= 6 else 2


# Generate possible package names by removing characters.
def _deletes(word: str, depth: int) -> set[str]:
    out, frontier = {word}, {word}
    for _ in range(depth):
        frontier = {w[:i] + w[i + 1 :] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


@dataclass(frozen=True)
class TopList:
    names: tuple[str, ...]
    index: dict[str, int] = field(default_factory=dict)  # name -> 1-based rank
    file: str = ""

    @classmethod
    def load(cls, path: Path = TOPLIST) -> TopList:
        """Load the popular npm package list and assign ranks."""
        names = tuple(json.loads(path.read_text())["names"])
        return cls(
            names,
            {n: i for i, n in enumerate(names, start=1)},
            path.relative_to(WORKSPACE).as_posix(),
        )


# Find suspicious package names similar to popular packages.
def typosquat_matches(candidates: set[str], top: TopList) -> dict[str, tuple[str, int, int]]:
    """candidate -> (closest popular name, rank, distance) for suspicious near-misses."""
    popular = [n for n in top.names[:TOP_N] if len(n) >= 4]
    by_delete: dict[str, set[str]] = defaultdict(set)
    for p in popular:
        for d in _deletes(p, max_distance(p)):
            by_delete[d].add(p)
    out = {}
    for c in sorted(candidates):
        if c in top.index or len(c) < 4:
            continue  # high-impact packages are not typosquats; very short names are noise
        near = set().union(*(by_delete.get(d, set()) for d in _deletes(c, max_distance(c))))
        best = None
        for p in sorted(near):
            dist = osa_distance(c, p)
            if 0 < dist <= min(max_distance(c), max_distance(p)):
                key = (dist, top.index[p])
                if best is None or key < best[0]:
                    best = (key, p)
        if best:
            (dist, rank), p = best
            out[c] = (p, rank, dist)
    return out


# --- lockfile helpers ------------------------------------------------------------------------


# Locate specific fields inside a lockfile entry.
def entry_field_line(lines: list[str], key_line: int | None, field_name: str) -> int | None:
    """Line number of `"field":` inside the lockfile entry starting at key_line."""
    if key_line is None:
        return None
    pattern = re.compile(rf'^\s*"{re.escape(field_name)}":')
    for number in range(key_line + 1, len(lines) + 1):
        text = lines[number - 1]
        if re.match(r"^    \}", text):
            return None
        if pattern.match(text):
            return number
    return None


# Check whether a package is recently published and rarely downloaded.
def _recent_and_rare(meta: dict, today: date | None = None) -> bool:
    created = date.fromisoformat(meta["created"][:10])
    age = ((today or datetime.now(UTC).date()) - created).days
    return age < RECENT_DAYS and int(meta["weekly_downloads"]) < LOW_DOWNLOADS


# Load package metadata from the mock registry.
def load_mock_registry(path: Path = MOCK_REGISTRY) -> dict:
    return json.loads(path.read_text())["packages"] if path.exists() else {}


@dataclass(frozen=True)
class Cite:
    """One fact to store as evidence (a guardian-rule line, or registry metadata)."""

    kind: EvidenceKind
    tool: str
    ref: str
    file: str
    line: int | None = None
    text: str | None = None


@dataclass
class AnomalyHit:
    """Represents a detected supply-chain anomaly."""
    rule: str
    node: str  # graph node (install path) of the affected package
    message: str
    cites: list[Cite]
    severity_override: Severity | None = None

    @property
    def severity(self) -> Severity:
        return self.severity_override or RULES[self.rule][0]

    @property
    def ftype(self) -> FindingType:
        return RULES[self.rule][1]


# Create evidence citations for lockfile lines.
def _line_cite(rule: str, file: str, lines: list[str], number: int | None) -> list[Cite]:
    if number is None:
        return []
    return [
        Cite(
            EvidenceKind.FILE_LOCATION,
            "guardian-rules",
            rule,
            file,
            number,
            lines[number - 1].strip(),
        )
    ]


# --- rules -------------------------------------------------------------------------------------


# Apply anomaly detection rules to a single lockfile.
def single_commit_rules(
    lock: NpmLock, top: TopList, registry_path: Path = MOCK_REGISTRY
) -> list[AnomalyHit]:
    registry = load_mock_registry(registry_path)
    registry_file = registry_path.relative_to(WORKSPACE).as_posix()
    lines = jail(lock.file).read_text().splitlines()
    hits: list[AnomalyHit] = []
    entries = {k: e for k, e in lock.entries.items() if k and not e.link}

    squats = typosquat_matches({e.name for e in entries.values()}, top)
    report_at: dict[str, str] = {}  # one typosquat finding per name: top-level path if present
    for key, e in entries.items():
        if e.name in squats and (e.name not in report_at or key == f"node_modules/{e.name}"):
            report_at[e.name] = key
    for key, e in entries.items():
        if report_at.get(e.name) == key:
            popular, rank, dist = squats[e.name]
            cites = _line_cite("GR-TYPO-001", lock.file, lines, e.line)
            cites.append(
                Cite(
                    EvidenceKind.REGISTRY_METADATA,
                    "npm-high-impact",
                    popular,
                    top.file,
                    None,
                    f"rank={rank} name={popular}; '{e.name}' not in "
                    f"list; distance={dist} ({classify(e.name, popular)})",
                )
            )
            meta = registry.get(e.name)
            severity = Severity.MEDIUM if dist == 1 else Severity.LOW
            if meta and _recent_and_rare(meta):
                severity = Severity.HIGH  # PDF: near-miss name plus low age or downloads
            if meta:
                cites.append(
                    Cite(
                        EvidenceKind.REGISTRY_METADATA,
                        "mock-registry",
                        e.name,
                        registry_file,
                        None,
                        f"created={meta['created']}; weekly_downloads={meta['weekly_downloads']}",
                    )
                )
            hits.append(
                AnomalyHit(
                    "GR-TYPO-001",
                    key,
                    f"'{e.name}' is {dist} edit(s) from "
                    f"popular package '{popular}' (rank {rank}, "
                    f"{classify(e.name, popular)})",
                    cites,
                    severity_override=severity,
                )
            )

        if e.has_install_script:
            script_line = entry_field_line(lines, e.line, "hasInstallScript")
            manifest = (registry.get(e.name) or {}).get("manifests", {}).get(e.version or "")
            suspicious = []
            if manifest:
                mlines = jail(manifest).read_text().splitlines()
                for number, text in enumerate(mlines, start=1):
                    m = re.match(r'^\s*"(preinstall|install|postinstall)":\s*"(.*)",?$', text)
                    if m and SUSPICIOUS.search(m.group(2)):
                        suspicious.append((number, m.group(1)))
            if suspicious:
                cites = _line_cite("GR-INST-002", lock.file, lines, script_line)
                for number, _ in suspicious:
                    cites += _line_cite("GR-INST-002", manifest, mlines, number)
                hits.append(
                    AnomalyHit(
                        "GR-INST-002",
                        key,
                        f"{suspicious[0][1]} script runs network or obfuscation commands",
                        cites,
                    )
                )
            else:
                hits.append(
                    AnomalyHit(
                        "GR-INST-001",
                        key,
                        "declares an install script "
                        "(lifecycle script runs on npm install); script not "
                        "inspected because the package is not installed",
                        _line_cite("GR-INST-001", lock.file, lines, script_line),
                    )
                )

        if e.resolved and not e.in_bundle:
            url = urlparse(e.resolved)
            resolved_line = entry_field_line(lines, e.line, "resolved")
            if url.netloc not in ALLOWED_HOSTS:
                mutable = re.search(
                    r"/(tarball|archive)/(master|main|HEAD)\b|#(master|main)$", e.resolved
                )
                hits.append(
                    AnomalyHit(
                        "GR-LOCK-001",
                        key,
                        f"resolved from '{url.netloc}', not "
                        "registry.npmjs.org" + (" (mutable branch ref)" if mutable else ""),
                        _line_cite("GR-LOCK-001", lock.file, lines, resolved_line),
                    )
                )
            else:
                base = e.name.rsplit("/", 1)[-1]
                if not url.path.endswith(f"/-/{base}-{e.version}.tgz"):
                    hits.append(
                        AnomalyHit(
                            "GR-LOCK-002",
                            key,
                            f"registry tarball URL does not match {e.name}@{e.version}",
                            _line_cite("GR-LOCK-002", lock.file, lines, resolved_line),
                        )
                    )
    return hits


# Extract the major version for dependency comparison.
def _major(version: str | None) -> str | None:
    if not version:
        return None
    m = re.match(r"(\d+)\.(\d+)", version)
    if not m:
        return None
    return m.group(1) if m.group(1) != "0" else f"0.{m.group(2)}"


# Detect lockfile changes and unexpected dependencies between commits.
def diff_rules(base: NpmLock, lock: NpmLock, graph: DependencyGraph) -> list[AnomalyHit]:
    """Rules that compare the target lockfile against its base commit's lockfile."""
    lines = jail(lock.file).read_text().splitlines()
    base_lines = jail(base.file).read_text().splitlines()
    hits: list[AnomalyHit] = []
    for key, e in lock.entries.items():
        b = base.entries.get(key)
        if not key or e.link or b is None or b.version != e.version:
            continue
        if b.integrity and e.integrity and b.integrity != e.integrity:
            cites = _line_cite(
                "GR-LOCK-004",
                base.file,
                base_lines,
                entry_field_line(base_lines, b.line, "integrity"),
            ) + _line_cite(
                "GR-LOCK-004", lock.file, lines, entry_field_line(lines, e.line, "integrity")
            )
            hits.append(
                AnomalyHit(
                    "GR-LOCK-004", key, f"integrity changed but version stayed {e.version}", cites
                )
            )
        if b.resolved and e.resolved and b.resolved != e.resolved:
            cites = _line_cite(
                "GR-LOCK-005",
                base.file,
                base_lines,
                entry_field_line(base_lines, b.line, "resolved"),
            ) + _line_cite(
                "GR-LOCK-005", lock.file, lines, entry_field_line(lines, e.line, "resolved")
            )
            hits.append(
                AnomalyHit(
                    "GR-LOCK-005",
                    key,
                    f"resolved URL changed but version stayed {e.version}",
                    cites,
                )
            )

    direct_names = {n.component.name for n in graph.nodes if n.direct}
    for key, e in lock.entries.items():
        if not key or key in base.entries or e.link or e.name in direct_names:
            continue
        if key not in {n.bom_ref for n in graph.nodes}:
            continue
        parents = graph.introduced_by(key)
        bumped = []
        for parent in parents:
            now, before = lock.entries.get(parent), base.entries.get(parent)
            if now and before and now.version != before.version:
                bumped.append((parent, before, now))
        same_major = [x for x in bumped if _major(x[1].version) == _major(x[2].version)]
        if bumped and len(same_major) == len(bumped):
            parent, before, now = same_major[0]
            cites = (
                _line_cite("GR-DEP-001", lock.file, lines, e.line)
                + _line_cite(
                    "GR-DEP-001",
                    base.file,
                    base_lines,
                    entry_field_line(base_lines, before.line, "version"),
                )
                + _line_cite(
                    "GR-DEP-001", lock.file, lines, entry_field_line(lines, now.line, "version")
                )
            )
            hits.append(
                AnomalyHit(
                    "GR-DEP-001",
                    key,
                    f"new transitive package added by a "
                    f"minor/patch bump of {now.name} ({before.version} -> "
                    f"{now.version})",
                    cites,
                )
            )
        elif not bumped:
            hits.append(
                AnomalyHit(
                    "GR-DEP-002",
                    key,
                    "new transitive package with no change to "
                    "any direct dependency that pulls it in",
                    _line_cite("GR-DEP-002", lock.file, lines, e.line),
                )
            )
    return hits


# Group anomaly findings and create evidence-backed drafts.
def anomaly_drafts(
    store: EvidenceStore, hits: list[AnomalyHit], graph: DependencyGraph
) -> list[Draft]:
    grouped: dict[tuple[str, FindingType], list[AnomalyHit]] = defaultdict(list)
    for h in hits:
        grouped[(h.node, h.ftype)].append(h)
    drafts: list[Draft] = []
    for (node_id, ftype), group in sorted(
        grouped.items(), key=lambda kv: (kv[0][0], kv[0][1].value)
    ):
        node = graph.node(node_id)
        runtime = node.scope is not DependencyScope.DEV
        path = (runtime and graph.shortest_path(node_id, exclude_dev=True)) or (
            graph.shortest_path(node_id)
        )
        refs: list[EvidenceRef] = []
        for h in sorted(group, key=lambda x: x.rule):
            for c in h.cites:
                rec = store.add(
                    ("anomaly", c.kind.value, c.tool, c.ref, c.file, c.line, c.text),
                    kind=c.kind,
                    tool=c.tool,
                    tool_version=(
                        f"guardian {__version__}" if c.tool == "guardian-rules" else None
                    ),
                    ref=c.ref,
                    file=c.file,
                    line=c.line,
                    excerpt=c.text,
                )
                if rec.id not in {r.evidence_id for r in refs}:
                    refs.append(ref_of(rec))
        rec = store.add(
            ("graph", node_id),
            kind=EvidenceKind.GRAPH_NODE,
            tool="dependency-graph",
            graph_node=node_id,
            excerpt=excerpt(" > ".join(graph.path_labels(path)) if path else node_id),
        )
        refs.append(ref_of(rec))
        top = max(group, key=lambda x: (SEVERITY_RANK[x.severity], x.rule))
        label = graph.label(node_id)
        drafts.append(
            (
                sort_key(False, False, top.severity, None, label, top.rule),
                {
                    "type": ftype,
                    "title": excerpt(f"{label}: {top.message}", 200),
                    "component": node.component,
                    "dependency_path": graph.path_labels(path) if path else (),
                    "introduced_by": tuple(graph.label(d) for d in graph.introduced_by(node_id))
                    if node_id != ROOT_ID
                    else (),
                    "advisory_ids": tuple(sorted({h.rule for h in group})),
                    "severity": top.severity,
                    "evidence": tuple(refs),
                    "factors": RiskFactors(
                        exposure=Exposure.BUILD_OR_DEV
                        if node.scope is DependencyScope.DEV
                        else Exposure.UNKNOWN
                    ),
                },
            )
        )
    return drafts
