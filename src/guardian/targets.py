"""Dynamic GitHub targets for the UI.

A user supplies an HTTPS GitHub repository URL. Guardian clones it read-only (depth 1, no tags,
no hooks, no LFS smudge, no submodules), pins the resolved commit, removes Git metadata, and
records the target in ``targets/dynamic.json`` so the normal pipeline can load it.

Only npm projects with a ``package-lock.json`` (lockfile v2/v3) are supported. Nothing from the
repository is executed; scanners still run offline.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from guardian.sbom.npm_lock import LockfileError, parse_lockfile
from guardian.tools.runner import WORKSPACE, workspace_relative

DYNAMIC_DIR = WORKSPACE / "targets" / "dynamic"
DYNAMIC_TARGETS_FILE = WORKSPACE / "targets" / "dynamic.json"
GIT_HOME = WORKSPACE / "cache" / "git-home"
GIT = "/usr/bin/git"
MAX_REPO_BYTES = 1024 * 1024 * 1024  # 1 GiB working tree
CLONE_TIMEOUT_S = 300
REPO_PATH = re.compile(r"^/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})/?$")


class DynamicTargetError(ValueError):
    pass


def parse_repo(url: str) -> tuple[str, str]:
    """Validate ``https://github.com/<owner>/<repo>`` and return (owner, repo)."""
    if not isinstance(url, str):
        raise DynamicTargetError("repository must be a string")
    text = url.strip()
    if not text or len(text) > 200:
        raise DynamicTargetError("repository URL is empty or too long")
    parsed = urlparse(text)
    if parsed.scheme != "https":
        raise DynamicTargetError("only https://github.com/... URLs are accepted")
    if parsed.hostname != "github.com":
        raise DynamicTargetError("only github.com repositories are accepted")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DynamicTargetError("credentials, query strings and fragments are not accepted")
    match = REPO_PATH.match(parsed.path)
    if not match:
        raise DynamicTargetError("expected https://github.com/<owner>/<repository>")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo in {".", ".."} or ".." in repo or not repo:
        raise DynamicTargetError("invalid repository name")
    return owner, repo


def _git(args: list[str], *, timeout: int = CLONE_TIMEOUT_S) -> subprocess.CompletedProcess:
    GIT_HOME.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(GIT_HOME),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    return subprocess.run(  # noqa: S603 - fixed /usr/bin/git, argv list, no shell
        [GIT, *args], cwd=WORKSPACE, env=env, capture_output=True, text=True,
        timeout=timeout, check=False,
    )  # fmt: skip


def _lock_tree(root: Path) -> None:
    """Make the clone read-only without following symlinks (which git did not create)."""
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            with contextlib.suppress(OSError):
                path.chmod(path.stat().st_mode & ~0o222)
    with contextlib.suppress(OSError):
        root.chmod(root.stat().st_mode & ~0o222)


def _register(target: dict) -> None:
    data: dict = {"targets": []}
    if DYNAMIC_TARGETS_FILE.exists():
        try:
            loaded = json.loads(DYNAMIC_TARGETS_FILE.read_text())
            if isinstance(loaded, dict) and isinstance(loaded.get("targets"), list):
                data = loaded
        except json.JSONDecodeError:
            data = {"targets": []}
    data["targets"] = [t for t in data["targets"] if t.get("name") != target["name"]]
    data["targets"].append(target)
    tmp = DYNAMIC_TARGETS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(DYNAMIC_TARGETS_FILE)


def prepare_target(repo_url: str, *, progress: Callable[[str], None] | None = None) -> dict:
    """Clone a GitHub repo, validate it, pin the commit and register it as a target."""
    owner, repo = parse_repo(repo_url)
    DYNAMIC_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"{owner}__{repo}-{stamp}"
    dest = DYNAMIC_DIR / name
    if dest.exists():
        raise DynamicTargetError(f"target directory already exists: {name}")
    url = f"https://github.com/{owner}/{repo}"

    if progress:
        progress(f"Cloning {url}")
    try:
        clone = _git(
            [
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.symlinks=false",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "filter.lfs.smudge=cat",
                "-c",
                "filter.lfs.process=",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--single-branch",
                "--filter=blob:limit=2m",
                url,
                str(dest),
            ]
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError(f"git clone timed out after {CLONE_TIMEOUT_S}s") from exc
    if clone.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError(f"git clone failed: {clone.stderr.strip()[-500:]}")

    head = _git(["-C", str(dest), "rev-parse", "HEAD"], timeout=30)
    commit = head.stdout.strip()
    if head.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError("could not resolve the cloned commit")
    shutil.rmtree(dest / ".git", ignore_errors=True)

    size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file() and not p.is_symlink())
    if size > MAX_REPO_BYTES:
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError(f"repository working tree is too large: {size} bytes")

    lock = dest / "package-lock.json"
    if not lock.is_file() or not (dest / "package.json").is_file():
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError(
            "only npm projects with package.json and package-lock.json are supported"
        )
    try:
        parse_lockfile(lock, workspace_relative(lock))
    except (LockfileError, ValueError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise DynamicTargetError(f"unsupported lockfile: {exc}") from exc

    target = {
        "name": name,
        "repo": url,
        "commit": commit,
        "commit_date": None,
        "license": "unknown",
        "ecosystem": "npm",
        "lockfile": "package-lock.json",
        "path": workspace_relative(dest),
        "read_only": True,
        "dynamic": True,
        "selected": "user-supplied GitHub repository (UI); commit pinned at clone time",
    }
    _register(target)
    _lock_tree(dest)
    if progress:
        progress(f"Pinned {owner}/{repo} at {commit[:12]}")
    return target
