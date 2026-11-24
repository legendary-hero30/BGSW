"""Regenerate package-lock.json for a work copy. This is the only networked step.

It is off unless GUARDIAN_ALLOW_REGISTRY_ACCESS=1. ``npm install --package-lock-only
--ignore-scripts`` resolves metadata and runs no package code. The environment is cleaned:
no user config, no tokens, a temporary HOME.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REGISTRY = "https://registry.npmjs.org/"


class RegistryAccessError(RuntimeError):
    pass


def allowed() -> bool:
    return os.environ.get("GUARDIAN_ALLOW_REGISTRY_ACCESS") == "1"


def regenerate(work: Path, timeout: int = 300) -> dict:
    if not allowed():
        raise RegistryAccessError(
            "regenerating the lockfile needs the npm registry. Set "
            "GUARDIAN_ALLOW_REGISTRY_ACCESS=1 to allow this one networked step."
        )
    npm = shutil.which("npm")
    if npm is None:
        raise RegistryAccessError("npm is not installed")
    with tempfile.TemporaryDirectory() as home:
        env = {
            "PATH": os.pathsep.join([str(Path(npm).parent), "/usr/bin", "/bin"]),
            "HOME": home,
            "NPM_CONFIG_USERCONFIG": "/dev/null",
            "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
            "NPM_CONFIG_CACHE": f"{home}/cache",
        }
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell, scripts disabled
            [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
             "--no-fund", "--registry", REGISTRY],
            cwd=work, env=env, capture_output=True, text=True, timeout=timeout, check=False,
        )  # fmt: skip
    if done.returncode:
        raise RegistryAccessError(f"npm failed: {(done.stderr or done.stdout).strip()[-400:]}")
    return {"command": "npm install --package-lock-only --ignore-scripts", "registry": REGISTRY}
