"""Sandbox policy and the docker command line. Pure checks plus honest availability handling."""

import pytest

from guardian import sandbox as sb
from guardian.sandbox import (
    DIGEST_RE,
    DockerSandbox,
    SandboxPolicy,
    SandboxUnavailableError,
    SbxSandbox,
    backend_report,
    check_policy,
    docker_command,
    select_sandbox,
)

IMAGE = "docker.io/library/node@sha256:" + "a" * 64


def policy(**kw) -> SandboxPolicy:
    return SandboxPolicy(image=IMAGE, mounts_ro=(("/work/target", "/target"),), **kw)


def flag_value(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_docker_command_sets_every_isolation_flag():
    cmd = docker_command("guardian-1", ["node", "-v"], policy(timeout_s=30))
    assert cmd[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert flag_value(cmd, "--network") == "none"
    assert "--read-only" in cmd
    assert flag_value(cmd, "--cap-drop") == "ALL"
    assert flag_value(cmd, "--security-opt") == "no-new-privileges"
    assert flag_value(cmd, "--user") == "65534:65534"  # nobody, never root
    assert flag_value(cmd, "--pull") == "never"  # nothing is fetched at run time
    assert flag_value(cmd, "--pids-limit") == "128"
    assert flag_value(cmd, "--memory") == flag_value(cmd, "--memory-swap")  # no swap escape
    assert "noexec" in flag_value(cmd, "--tmpfs")
    assert cmd[-3:] == [IMAGE, "node", "-v"]  # the command is argv, never a shell string


def test_mounts_are_read_only_bind_mounts_and_nothing_else_is_mounted():
    cmd = docker_command("g", ["ls"], policy())
    mounts = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--mount"]
    assert mounts == ["type=bind,source=/work/target,target=/target,readonly"]
    assert "-v" not in cmd and "--volume" not in cmd and "--env" not in cmd and "-e" not in cmd


def test_the_docker_socket_and_privileges_are_never_requested():
    cmd = " ".join(docker_command("g", ["ls"], policy()))
    assert "docker.sock" not in cmd and "--privileged" not in cmd and "--network host" not in cmd


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"image": "node:20"}, "not digest-pinned"),
        ({"image": "node@sha256:abc"}, "not digest-pinned"),
        ({"mounts_ro": (("relative/path", "/t"),)}, "bad mount"),
        ({"mounts_ro": (("/abs", "no-slash"),)}, "bad mount"),
        ({"mounts_ro": (("/abs", "/a/../etc"),)}, "bad mount"),
        ({"timeout_s": 0}, "timeout_s"),
        ({"timeout_s": 601}, "timeout_s"),
    ],
)
def test_policy_refuses_unsafe_requests(kwargs, message):
    base = {"image": IMAGE, "mounts_ro": (), "timeout_s": 30} | kwargs
    with pytest.raises(SandboxUnavailableError, match=message):
        check_policy(SandboxPolicy(**base))


def test_digest_pattern():
    assert DIGEST_RE.match(IMAGE) and not DIGEST_RE.match("x@sha256:" + "g" * 64)


def test_selection_never_returns_a_backend_that_cannot_run(monkeypatch):
    monkeypatch.setattr(DockerSandbox, "available", lambda self: (False, "daemon is down"))
    backend, reason = select_sandbox("auto")
    assert backend is None and "daemon is down" in reason

    monkeypatch.setattr(DockerSandbox, "available", lambda self: (True, "docker engine 29"))
    monkeypatch.delenv(sb.IMAGE_ENV, raising=False)
    backend, reason = select_sandbox("auto")
    assert backend is None and sb.IMAGE_ENV in reason  # docker alone is not enough

    monkeypatch.setenv(sb.IMAGE_ENV, "node:latest")
    assert select_sandbox("docker")[0] is None  # unpinned image: refused
    monkeypatch.setenv(sb.IMAGE_ENV, IMAGE)
    backend, reason = select_sandbox("docker")
    assert isinstance(backend, DockerSandbox) and "docker engine" in reason


def test_selection_none_and_unknown():
    backend, reason = select_sandbox("none")
    assert backend is None and "refuse" in reason
    with pytest.raises(ValueError, match="unknown sandbox"):
        select_sandbox("sbx")  # detection-only backend cannot be selected to run commands


def test_docker_run_without_a_daemon_raises_instead_of_running_on_the_host(monkeypatch):
    monkeypatch.setattr(DockerSandbox, "available", lambda self: (False, "no daemon"))
    with pytest.raises(SandboxUnavailableError, match="no daemon"):
        DockerSandbox().run(["id"], policy())


def test_sbx_is_detection_only_and_says_why():
    ok, detail = SbxSandbox().available()
    assert isinstance(ok, bool) and detail
    with pytest.raises(SandboxUnavailableError, match="detection-only"):
        SbxSandbox().run(["id"], policy())


def test_backend_report_lists_both_backends():
    report = backend_report()
    assert set(report) == {"docker", "sbx"}
    assert all(set(v) == {"available", "detail"} for v in report.values())
