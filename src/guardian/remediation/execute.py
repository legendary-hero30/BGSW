"""Build and test a work copy. Package code runs ONLY inside the namespace sandbox.

Installing dependencies is the one networked step and runs no package code
(``npm ci --ignore-scripts``, clean environment, same opt-in as the lockfile step). The build and
the tests then run in bubblewrap with no network, no capabilities and a read-only work tree.

A test result is only attributed to the fix by comparing with the same tests on an unmodified
copy: a suite that already fails (or cannot run) before the change proves nothing after it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from guardian.remediation import lockfile
from guardian.sandbox import BwrapSandbox, ExecSpec, SandboxResult, SandboxUnavailableError

PLACEHOLDER = "no test specified"


def node_root() -> Path:
    node = shutil.which("node")
    if node is None:
        raise SandboxUnavailableError("node is not installed")
    return Path(node).resolve().parents[1]


def install(work: Path, timeout: int = 600) -> dict:
    """npm ci with lifecycle scripts disabled. Needs the registry."""
    if not lockfile.allowed():
        raise lockfile.RegistryAccessError(
            "installing dependencies needs GUARDIAN_ALLOW_REGISTRY_ACCESS=1"
        )
    npm = shutil.which("npm")
    if npm is None:
        raise lockfile.RegistryAccessError("npm is not installed")
    with tempfile.TemporaryDirectory() as home:
        env = {
            "PATH": os.pathsep.join([str(Path(npm).parent), "/usr/bin", "/bin"]),
            "HOME": home,
            "NPM_CONFIG_USERCONFIG": f"{home}/user.npmrc",  # empty, so no user tokens are read
            "NPM_CONFIG_GLOBALCONFIG": f"{home}/global.npmrc",
            "NPM_CONFIG_CACHE": f"{home}/cache",
        }
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell, scripts disabled
            [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
             "--registry", lockfile.REGISTRY],
            cwd=work, env=env, capture_output=True, text=True, timeout=timeout, check=False,
        )  # fmt: skip
    if done.returncode:
        raise lockfile.RegistryAccessError(
            f"npm ci failed: {(done.stderr or done.stdout).strip()[-400:]}"
        )
    return {"installed": True}


def scripts_of(work: Path) -> dict[str, str]:
    path = work / "package.json"
    return json.loads(path.read_text()).get("scripts", {}) if path.is_file() else {}


def run_script(work: Path, name: str, timeout_s: int = 300) -> SandboxResult:
    root = node_root()
    spec = ExecSpec(
        work=str(work.resolve()),
        ro_paths=(str(root),),
        path_env=f"{root}/bin:/usr/bin:/bin",
        timeout_s=timeout_s,
    )
    return BwrapSandbox().run_spec([str(root / "bin" / "npm"), "run", name, "--silent"], spec)


def step(work: Path, name: str) -> dict:
    """One sandboxed npm script: passed / failed / not_run (with the reason)."""
    ok, why = BwrapSandbox().available()
    if not ok:
        return {"status": "not_run", "detail": f"no sandbox: {why}"}
    scripts = scripts_of(work)
    cmd = scripts.get(name)
    if not cmd or PLACEHOLDER in cmd:
        return {"status": "not_run", "detail": f"package.json has no real '{name}' script"}
    r = run_script(work, name)
    tail = (r.stdout + r.stderr).strip()[-600:]
    status = "passed" if r.returncode == 0 and not r.timed_out else "failed"
    return {
        "status": status, "sandbox": r.backend, "command": f"npm run {name}",
        "exit_code": r.returncode, "seconds": round(r.duration_s, 1),
        "timed_out": r.timed_out, "output_tail": tail,
    }  # fmt: skip


def attribute(after: dict, baseline: dict) -> dict:
    """Decide whether a result is evidence about the fix, using the unmodified copy."""
    if after["status"] != "failed":
        return after
    if baseline["status"] == "passed":
        return {**after, "detail": "passes on the unmodified copy: a regression from the fix"}
    return {
        **after, "status": "not_run",
        "detail": f"also {baseline['status']} on the unmodified copy; "
        "the result says nothing about the fix",
    }  # fmt: skip
