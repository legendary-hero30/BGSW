"""Isolated execution for anything that touches untrusted content (AGENTS.md section 2).

Tool tiers:
  * read:  parse files in the path-jailed workspace. No isolation needed.
  * scan:  pinned scanner binaries, offline in an empty network namespace (``tools.runner``).
  * exec:  run *any* command whose input is untrusted (tarballs, install scripts, target code).
           Only ever inside a sandbox. With no sandbox the tool refuses; there is no host fallback.

Backends:
  * ``docker``: plain ``docker run`` with every isolation flag set below. The command is built by
    a pure function so each flag is unit-tested. Needs a running daemon and a digest-pinned image.
  * ``sbx``: Docker Sandboxes (microVMs). Detected, not driven: its network policy is global
    (``sbx policy``), and Guardian will not change a user's global policy to obtain "no network".
    To run the whole supervisor inside an sbx sandbox with network limited to the model API, see
    SETUP.md ("Process-level isolation").
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from guardian.redact import redact

IMAGE_ENV = "GUARDIAN_SANDBOX_IMAGE"
DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
MAX_OUTPUT = 64 * 1024
DOCKER = "/usr/bin/docker"
SBX = "sbx"


class SandboxUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    image: str
    mounts_ro: tuple[tuple[str, str], ...] = ()  # (host path, container path), always read-only
    memory: str = "256m"
    cpus: str = "1"
    pids: int = 128
    tmpfs_mb: int = 64
    timeout_s: int = 60
    workdir: str = "/tmp"  # noqa: S108 - the container's own tmpfs, never the host's /tmp


@dataclass(frozen=True)
class SandboxResult:
    backend: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


class Sandbox(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...

    def run(self, argv: list[str], policy: SandboxPolicy) -> SandboxResult: ...


def check_policy(policy: SandboxPolicy) -> None:
    if not DIGEST_RE.match(policy.image):
        raise SandboxUnavailableError(
            f"sandbox image {policy.image!r} is not digest-pinned (name@sha256:<64 hex>); "
            "unpinned images are not trusted"
        )
    for host, ctr in policy.mounts_ro:
        if not Path(host).is_absolute() or not ctr.startswith("/") or ".." in ctr.split("/"):
            raise SandboxUnavailableError(f"bad mount {host!r} -> {ctr!r}")
    if not 1 <= policy.timeout_s <= 600:
        raise SandboxUnavailableError("timeout_s must be between 1 and 600")


def docker_command(name: str, argv: list[str], policy: SandboxPolicy) -> list[str]:
    """The exact ``docker run`` invocation. Pure, so every flag is testable."""
    check_policy(policy)
    cmd = [
        DOCKER,
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        "guardian=sandbox",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(policy.pids),
        "--memory",
        policy.memory,
        "--memory-swap",
        policy.memory,
        "--cpus",
        policy.cpus,
        "--user",
        "65534:65534",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={policy.tmpfs_mb}m",  # noqa: S108 - inside the container
        "--workdir",
        policy.workdir,
        "--pull",
        "never",
    ]
    for host, ctr in policy.mounts_ro:
        cmd += ["--mount", f"type=bind,source={host},target={ctr},readonly"]
    return [*cmd, policy.image, *argv]


def _clip(data: bytes) -> str:
    text = data[:MAX_OUTPUT].decode(errors="replace")
    return redact(text) + (
        f"\n…[+{len(data) - MAX_OUTPUT} bytes]" if len(data) > MAX_OUTPUT else ""
    )


class DockerSandbox:
    name = "docker"

    def available(self) -> tuple[bool, str]:
        if not Path(DOCKER).exists():
            return False, "docker CLI not found at /usr/bin/docker"
        try:
            proc = subprocess.run(  # noqa: S603 - fixed binary, fixed argv
                [DOCKER, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                timeout=15,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return False, "docker daemon did not answer within 15s"
        if proc.returncode != 0:
            first = proc.stderr.decode(errors="replace").strip().splitlines()[:1]
            return False, f"docker daemon is not reachable ({first[0] if first else 'no detail'})"
        return True, f"docker engine {proc.stdout.decode().strip()}"

    def run(self, argv: list[str], policy: SandboxPolicy) -> SandboxResult:
        ok, why = self.available()
        if not ok:
            raise SandboxUnavailableError(why)
        name = f"guardian-{uuid4().hex[:10]}"
        cmd = docker_command(name, argv, policy)
        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, policy checked above
                cmd,
                capture_output=True,
                timeout=policy.timeout_s,
                check=False,
                stdin=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            )
        except subprocess.TimeoutExpired:
            subprocess.run(  # noqa: S603
                [DOCKER, "rm", "-f", name], capture_output=True, timeout=30, check=False
            )
            return SandboxResult(self.name, -1, "", "timed out", time.monotonic() - start, True)
        return SandboxResult(
            self.name,
            proc.returncode,
            _clip(proc.stdout),
            _clip(proc.stderr),
            time.monotonic() - start,
        )


class SbxSandbox:
    """Docker Sandboxes (``sbx``): detection only. See the module docstring."""

    name = "sbx"

    def available(self) -> tuple[bool, str]:
        if shutil.which(SBX) is None:
            return False, (
                "sbx is not installed (Docker Sandboxes need Ubuntu 24.04+ with KVM; "
                "WSL2 is not listed as supported)"
            )
        return True, "sbx is installed"

    def run(self, argv: list[str], policy: SandboxPolicy) -> SandboxResult:
        raise SandboxUnavailableError(
            "the sbx backend is detection-only: its network policy is global and Guardian will "
            "not change it. Use the docker backend for tool isolation, or run the whole "
            "supervisor inside sbx (SETUP.md, 'Process-level isolation')."
        )


def backend_report() -> dict[str, dict]:
    """Availability of each backend, for the run record and the API."""
    return {
        b.name: dict(zip(("available", "detail"), b.available(), strict=True))
        for b in (DockerSandbox(), SbxSandbox())
    }


def select_sandbox(preference: str = "auto") -> tuple[Sandbox | None, str]:
    """Pick a backend that can actually run commands. Returns (backend or None, reason)."""
    if preference == "none":
        return None, "sandboxing disabled by the caller (exec-tier tools will refuse)"
    if preference not in {"auto", "docker"}:
        raise ValueError(f"unknown sandbox {preference!r}; choose auto, docker or none")
    docker = DockerSandbox()
    ok, why = docker.available()
    if not ok:
        return None, f"no usable sandbox: {why}"
    if not DIGEST_RE.match(os.environ.get(IMAGE_ENV, "")):
        return None, f"docker is available but {IMAGE_ENV} is not set to a digest-pinned image"
    return docker, why
