"""Server-side push: off by default, typed confirmation, new branch only, token never leaks."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from guardian.remediation import push
from guardian.remediation.proposals import ApprovalError

TOKEN = "ghp_SECRET_TOKEN_VALUE"  # noqa: S105 - fake


def sh(cwd, *a):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=True).stdout  # noqa: S603, S607


@pytest.fixture
def remote(tmp_path, monkeypatch):
    bare = tmp_path / "remote.git"
    sh(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    sh(tmp_path, "init", "-q", "-b", "main", str(seed))
    (seed / "package.json").write_text('{"a": 1}\n')
    (seed / "package-lock.json").write_text("{}\n")
    sh(seed, "add", "-A")
    sh(seed, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")
    sh(seed, "push", "-q", str(bare), "main")
    base = sh(seed, "rev-parse", "HEAD").strip()
    (seed / "package.json").write_text('{"a": 2}\n')
    patch = tmp_path / "R-001.patch"
    patch.write_text(sh(seed, "diff", "--", "package.json"))
    meta = {
        "repo": f"https://github.com/me/app",  # noqa: F541
        "base_commit": base,
        "branch": "guardian/fix-f-001",
        "title": "guardian: bump a",
        "approved_by": "Human",
        "metadata_file": str(tmp_path / "R-001.json"),
    }
    monkeypatch.setattr(push, "export_fix", lambda *a: dict(meta))
    monkeypatch.setattr(push, "jail", lambda p: Path(p))
    monkeypatch.setattr(push, "WORKSPACE", tmp_path)
    # point the clone at the local bare repo instead of github
    real = push._git

    def fake(cwd, home, token, *args):
        args = tuple(str(bare) if a == "https://github.com/me/app" else a for a in args)
        return real(cwd, home, token, *args)

    monkeypatch.setattr(push, "_git", fake)
    return bare


def test_off_by_default(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ALLOW_PUSH", raising=False)
    monkeypatch.setenv("GUARDIAN_GITHUB_TOKEN", TOKEN)
    with pytest.raises(push.PushError, match="pushing is off"):
        push.push_fix("x", "r", "R-001", "me/app")


def test_needs_the_typed_repo_name(remote, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_PUSH", "1")
    monkeypatch.setenv("GUARDIAN_GITHUB_TOKEN", TOKEN)
    with pytest.raises(ApprovalError, match="exactly"):
        push.push_fix("x", "r", "R-001", "wrong/name")


def test_pushes_a_new_branch_only(remote, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_PUSH", "1")
    monkeypatch.setenv("GUARDIAN_GITHUB_TOKEN", TOKEN)
    out = push.push_fix("x", "r", "R-001", "me/app")
    assert out["pushed"] and out["branch"] == "guardian/fix-f-001"
    assert TOKEN not in str(out)
    branches = sh(remote, "branch", "--list").split()
    assert "guardian/fix-f-001" in branches and "main" in branches
    assert sh(remote, "show", "main:package.json").strip() == '{"a": 1}'  # default untouched
    assert sh(remote, "show", "guardian/fix-f-001:package.json").strip() == '{"a": 2}'


def test_errors_never_contain_the_token(remote, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_PUSH", "1")
    monkeypatch.setenv("GUARDIAN_GITHUB_TOKEN", TOKEN)
    other = remote.parent / "other"
    sh(remote.parent, "clone", "-q", str(remote), str(other))
    sh(other, "checkout", "-q", "-b", "guardian/fix-f-001")
    (other / "x.txt").write_text("diverged\n")
    sh(other, "add", "-A")
    sh(other, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
    sh(other, "push", "-q", "origin", "guardian/fix-f-001")
    with pytest.raises(push.PushError) as e:  # a diverged remote branch is never overwritten
        push.push_fix("x", "r", "R-001", "me/app")
    assert TOKEN not in str(e.value)
