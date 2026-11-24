"""Push an approved, validated fix as a NEW branch, using a token you supplied.

Off unless GUARDIAN_ALLOW_PUSH=1 and GUARDIAN_GITHUB_TOKEN is set (in .env or the environment).
The token is read only here, at push time, and goes to git only through a throw-away askpass
helper and the child's environment: never in argv, a URL, a file the repo can see, a log or a
response. Agents have no tool that reaches this code. It cannot push the default branch, cannot
force, and never merges or opens a pull request: a person does that.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from guardian.remediation.export import export_fix
from guardian.remediation.proposals import ApprovalError
from guardian.tools.runner import WORKSPACE, jail

log = logging.getLogger("guardian.push")
GIT = shutil.which("git") or "/usr/bin/git"
BRANCH = re.compile(r"^guardian/fix-[a-z0-9._-]+$")


class PushError(RuntimeError):
    pass


# Push is on only with GUARDIAN_ALLOW_PUSH=1 and a token in the environment.
def allowed() -> bool:
    return os.environ.get("GUARDIAN_ALLOW_PUSH") == "1" and bool(
        os.environ.get("GUARDIAN_GITHUB_TOKEN")
    )


# Run git with the token available only to the child, via a temporary askpass helper.
def _git(cwd: Path, home: Path, token: str, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": str(home / "askpass.sh"),
        "GUARDIAN_PUSH_TOKEN": token,
    }
    done = subprocess.run(  # noqa: S603 - fixed git binary, argv list, no shell
        [GIT, "-c", "core.hooksPath=/dev/null", "-c", "user.name=guardian",
         "-c", "user.email=guardian@users.noreply.github.com", "-c", "commit.gpgsign=false",
         *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    if done.returncode:
        text = (done.stderr or done.stdout).replace(token, "***").strip()[-400:]
        log.warning("git %s failed: %s", args[0], text[:120])
        raise PushError(f"git {args[0]} failed: {text}")
    return done.stdout


# Re-check approval, clone fresh, apply the patch on a new branch and push it.
def push_fix(db: str, run_id: str, proposal_id: str, confirm_repo: str) -> dict:
    if not allowed():
        raise PushError(
            "pushing is off: set GUARDIAN_ALLOW_PUSH=1 and GUARDIAN_GITHUB_TOKEN in .env and "
            "restart the server (or use scripts/push_fix.sh with your own git login)"
        )
    token = os.environ["GUARDIAN_GITHUB_TOKEN"]
    meta = export_fix(db, run_id, proposal_id)  # re-checks approval hash and the verdict
    slug = meta["repo"].removeprefix("https://github.com/")
    if confirm_repo.strip() != slug:
        raise ApprovalError(f"type the repository name exactly ({slug}) to confirm the push")
    if not BRANCH.match(meta["branch"]):
        raise PushError(f"refusing branch name {meta['branch']!r}")
    patch = jail(meta["metadata_file"]).with_suffix(".patch")

    work = Path(tempfile.mkdtemp(prefix="guardian-push-"))
    try:
        ask = work / "askpass.sh"
        ask.write_text('#!/bin/sh\ncase "$1" in *sername*) echo x-access-token;;'
                       ' *) echo "$GUARDIAN_PUSH_TOKEN";; esac\n')
        ask.chmod(stat.S_IRWXU)
        repo = work / "repo"
        _git(work, work, token, "clone", "--quiet", meta["repo"], str(repo))
        default = _git(repo, work, token, "rev-parse", "--abbrev-ref", "HEAD").strip()
        if meta["branch"] == default:
            raise PushError("refusing to push the default branch")
        moved = _git(repo, work, token, "rev-parse", "HEAD").strip() != meta["base_commit"]
        _git(repo, work, token, "apply", "--check", str(patch))
        _git(repo, work, token, "checkout", "--quiet", "-b", meta["branch"])
        _git(repo, work, token, "apply", str(patch))
        _git(repo, work, token, "add", "package.json", "package-lock.json")
        _git(repo, work, token, "commit", "--quiet", "-m", meta["title"], "-m",
             f"Prepared by Software Supply Chain Guardian; approved by {meta['approved_by']}. "
             "Review before merging.")  # fmt: skip
        log.info("pushing %s to %s", meta["branch"], meta["repo"])  # never the token
        _git(repo, work, token, "push", "--set-upstream", "origin", meta["branch"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    log.info("pushed %s", meta["branch"])
    result = {
        "pushed": True,
        "repo": meta["repo"],
        "branch": meta["branch"],
        "default_branch": default,
        "default_branch_moved": moved,
        "compare_url": f"{meta['repo']}/compare/{default}...{meta['branch']}?expand=1",
    }
    done = WORKSPACE / jail(meta["metadata_file"]).relative_to(WORKSPACE)
    done.with_suffix(".pushed.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
