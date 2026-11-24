"""Isolated working copy for a remediation: a git branch in a copy, never the original target.

The copy lives under targets/work/, is its own git repository with hooks disabled, and is
registered as a dynamic target (``base_target`` names the original) so the normal scan stages
can run on it. The original checkout is never written.
"""

from __future__ import annotations

import difflib
import json
import shutil
import subprocess
from pathlib import Path

from guardian.remediation.schemas import Edit, Proposal
from guardian.sbom.build import load_target
from guardian.targets import _register
from guardian.tools.runner import WORKSPACE, jail

WORK_DIR = WORKSPACE / "targets" / "work"
GIT = shutil.which("git") or "/usr/bin/git"
SKIP = shutil.ignore_patterns(".git", "node_modules", ".env", ".env.*")


class WorkspaceError(RuntimeError):
    pass


def git(cwd: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(WORK_DIR),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    cmd = [GIT, "-c", "core.hooksPath=/dev/null", "-c", "user.name=guardian",
           "-c", "user.email=guardian@localhost", "-c", "commit.gpgsign=false", *args]  # fmt: skip
    done = subprocess.run(  # noqa: S603 - fixed git binary, argv list, no shell
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    if done.returncode:
        raise WorkspaceError(f"git {args[0]} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def apply_edit(manifest: dict, edit: Edit) -> dict:
    """Return a copy of package.json with one edit applied; refuse if it does not match."""
    out = json.loads(json.dumps(manifest))
    section = out.setdefault(edit.section, {})
    current = section.get(edit.package)
    if edit.op == "set_dependency" and current != edit.from_spec:
        raise WorkspaceError(
            f"package.json has {edit.package}={current!r}, the proposal expected {edit.from_spec!r}"
        )
    section[edit.package] = edit.to_spec
    return out


def diff_text(before: str, after: str, name: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(True), after.splitlines(True), f"a/{name}", f"b/{name}"
        )
    )


def create(base_target: str, p: Proposal) -> dict:
    """Copy the target, branch, apply the proposal's edits to package.json and commit."""
    if not p.applicable or not p.edits:
        raise WorkspaceError("this proposal has no edits to apply")
    base = load_target(base_target)
    src = jail(base["path"])
    slug = f"{base_target}-{p.id}".replace(":", "-").lower()
    dest = WORK_DIR / slug
    if dest.exists():
        shutil.rmtree(dest)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, ignore=SKIP, symlinks=False)
    for path in [dest, *dest.rglob("*")]:  # a clone may be read-only
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | 0o200)
    git(dest, "init", "-q", "-b", "base")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "base: copy of target before remediation")
    branch = f"guardian/fix-{p.finding_id}"
    git(dest, "checkout", "-q", "-b", branch)

    pj = dest / "package.json"
    before_text = pj.read_text()
    manifest = json.loads(before_text)
    for edit in p.edits:
        manifest = apply_edit(manifest, edit)
    after_text = json.dumps(manifest, indent=2) + "\n"
    pj.write_text(after_text)
    git(dest, "add", "package.json")
    git(dest, "commit", "-q", "-m", f"guardian: {p.summary[:200]}")
    commit = git(dest, "rev-parse", "HEAD").strip()

    target = {
        **{k: v for k, v in base.items() if k not in {"read_only", "selected"}},
        "name": f"work-{slug}",
        "path": str(dest.relative_to(WORKSPACE)),
        "dynamic": True,
        "base_target": base_target,
        "selected": f"remediation work copy for {p.id} (branch {branch})",
    }
    _register(target)
    return {
        "target": target["name"],
        "path": target["path"],
        "branch": branch,
        "commit": commit,
        "diff": diff_text(before_text, after_text, "package.json"),
    }


def read_manifest(target: str) -> dict | None:
    t = load_target(target)
    path = jail(Path(t["path"]) / "package.json")
    return json.loads(path.read_text()) if path.is_file() else None


def baseline_copy(base_target: str, p: Proposal) -> Path:
    """An unmodified copy of the target (no node_modules), for comparing build/test results."""
    base = load_target(base_target)
    dest = WORK_DIR / f"{base_target}-{p.id}-baseline".replace(":", "-").lower()
    if dest.exists():
        shutil.rmtree(dest)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(jail(base["path"]), dest, ignore=SKIP, symlinks=False)
    for path in [dest, *dest.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | 0o200)
    return dest
