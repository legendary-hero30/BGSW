"""Isolated execution for anything that touches untrusted content (AGENTS.md section 2).

Tool tiers:
  * read:  parse files in the path-jailed workspace. No isolation needed.
  * scan:  pinned scanner binaries, offline in an empty network namespace (``tools.runner``).
  * exec:  run *any* command whose input is untrusted (tarballs, install scripts, target code).
           Only ever inside a sandbox. With no sandbox the tool refuses; there is no host fallback.

Backends:
  * ``docker``: plain ``docker run`` with every isolation flag set below. The command is built by
    a pure function so each flag is unit-tested. Needs a running daemon and a digest-pinned image.
  * ``bwrap``: bubblewrap (Linux namespaces: user, pid, net, ipc, uts, cgroup). Same properties
    as the container flags above: no network, no capabilities, read-only filesystem, tmpfs
    scratch, no home directory, killed with its parent. It uses the host's toolchain read-only
    instead of an image. Used for build and test execution. Needs no daemon and no root.
  * ``sbx``: Docker Sandboxes (microVMs). Detected, not driven: its network policy is global
    (``sbx policy``), and Guardian will not change a user's global policy to obtain "no network".
    To run the whole supervisor inside an sbx sandbox with network limited to the model API, see
    SETUP.md ("Process-level isolation").
"""

from __future__ import annotations

import os
import re
import resource
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
BWRAP = "/usr/bin/bwrap"
SBX = "sbx"


class SandboxUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
# What untrusted code may do: no network, resource caps, read-only mounts.
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


# Refuse policies that would weaken isolation.
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


# Build the docker run argv (dropped caps, no network, read-only root).
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


# Runs untrusted code in a container. Unit-tested; no daemon here to run it.
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


@dataclass(frozen=True)
# What a bubblewrap run needs: tree to expose, writable dirs, env, limits.
class ExecSpec:
    """A command to run in a namespace sandbox. The work directory is mounted read-only."""

    work: str  # absolute host directory, mounted read-only at /work
    ro_paths: tuple[str, ...] = ()  # extra absolute host paths mounted read-only at the same path
    path_env: str = "/usr/bin:/bin"
    timeout_s: int = 300
    memory_mb: int = 2048
    nproc: int = 512


# Build the bubblewrap argv (new namespaces, no network, read-only tree).
def bwrap_command(argv: list[str], spec: ExecSpec) -> list[str]:
    """The exact bubblewrap invocation. Pure, so every flag is testable."""
    if not Path(spec.work).is_absolute():
        raise SandboxUnavailableError("work directory must be absolute")
    for p in spec.ro_paths:
        if not Path(p).is_absolute() or ".." in Path(p).parts:
            raise SandboxUnavailableError(f"bad read-only path {p!r}")
    if not 1 <= spec.timeout_s <= 900:
        raise SandboxUnavailableError("timeout_s must be between 1 and 900")
    cmd = [
        BWRAP, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--ro-bind", "/etc/ssl", "/etc/ssl", "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",  # noqa: S108 - inside the sandbox
        "--clearenv", "--setenv", "PATH", spec.path_env, "--setenv", "HOME", "/tmp",  # noqa: S108 - the sandbox tmpfs
        "--setenv", "CI", "1", "--setenv", "NODE_ENV", "test",
    ]  # fmt: skip
    for p in spec.ro_paths:
        cmd += ["--ro-bind", p, p]
    cmd += ["--ro-bind", spec.work, "/work", "--chdir", "/work"]
    return [*cmd, "--", *argv]


# Namespace sandbox that works without root; used for build and test here.
class BwrapSandbox:
    name = "bwrap"

    def available(self) -> tuple[bool, str]:
        if not Path(BWRAP).exists():
            return False, "bubblewrap (/usr/bin/bwrap) is not installed"
        probe = subprocess.run(  # noqa: S603 - fixed binary and argv
            [BWRAP, "--unshare-all", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
             "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
             "--", "/usr/bin/true"],
            capture_output=True, timeout=15, check=False, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        if probe.returncode:
            first = probe.stderr.decode(errors="replace").strip().splitlines()[:1]
            return False, f"bubblewrap cannot create namespaces ({first[0] if first else '?'})"
        return True, "bubblewrap namespaces (no network, no capabilities, read-only root)"

    def run_spec(self, argv: list[str], spec: ExecSpec) -> SandboxResult:
        ok, why = self.available()
        if not ok:
            raise SandboxUnavailableError(why)
        cmd = bwrap_command(argv, spec)
        limit = spec.memory_mb * 1024 * 1024

        def limits() -> None:  # runs in the child before exec
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            resource.setrlimit(resource.RLIMIT_NPROC, (spec.nproc, spec.nproc))

        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, spec checked above
                cmd, capture_output=True, timeout=spec.timeout_s, check=False,
                stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"}, preexec_fn=limits,
            )  # fmt: skip
        except subprocess.TimeoutExpired:
            return SandboxResult(self.name, -1, "", "timed out", time.monotonic() - start, True)
        return SandboxResult(
            self.name, proc.returncode, _clip(proc.stdout), _clip(proc.stderr),
            time.monotonic() - start,
        )  # fmt: skip


# Docker sbx microVM backend: detected, not executed.
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


# Which sandbox backends are usable on this machine, and why not if not.
def backend_report() -> dict[str, dict]:
    """Availability of each backend, for the run record and the API."""
    return {
        b.name: dict(zip(("available", "detail"), b.available(), strict=True))
        for b in (DockerSandbox(), BwrapSandbox(), SbxSandbox())
    }


# Pick a backend by preference; None means untrusted code is not run at all.
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
