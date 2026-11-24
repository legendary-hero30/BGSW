"""The bundled demo app (demo/vulnerable-app): two outdated dependencies, a real build and tests.

Copied (never edited in place) to targets/dynamic/ under a fresh name per run and registered as a
dynamic target, so repeated demos do not overwrite each other.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime

from guardian.targets import _register
from guardian.tools.runner import WORKSPACE

SRC = WORKSPACE / "demo" / "vulnerable-app"
NAME = "guardian-demo-app"

GOAL_ASSESS = (
    "Assess the software supply-chain risk of this repository. Find what is in it, what is "
    "vulnerable, and what looks suspicious beyond known CVEs. Report the few things that matter "
    "most, with evidence, what was not checked, and what to do next."
)
GOAL_REMEDIATE = (
    "Assess this application's supply-chain risk. Then, for the highest-risk findings that have "
    "a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at "
    "the human approval gate and report the pending proposals with their expected risk "
    "reduction, compatibility impact and rollback."
)


def prepare_demo_target() -> dict:
    if not (SRC / "package-lock.json").is_file():
        raise FileNotFoundError("demo/vulnerable-app is missing")
    name = f"{NAME}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    dest = WORKSPACE / "targets" / "dynamic" / name
    shutil.copytree(SRC, dest, ignore=shutil.ignore_patterns("node_modules"))
    target = {
        "name": name,
        "repo": "bundled demo app (demo/vulnerable-app)",
        "commit": hashlib.sha256((dest / "package-lock.json").read_bytes()).hexdigest()[:40],
        "commit_date": None,
        "license": "MIT",
        "ecosystem": "npm",
        "lockfile": "package-lock.json",
        "path": str(dest.relative_to(WORKSPACE)),
        "read_only": False,
        "dynamic": True,
        "selected": "bundled remediation demo app",
    }
    _register(target)
    return target
