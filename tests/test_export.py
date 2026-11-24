"""Export of an approved, validated fix: gates, patch content, and the push script's refusals."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from guardian.remediation import export, workspace
from guardian.remediation.engine import propose
from guardian.remediation.proposals import ApprovalError, add_proposal, add_validation, decide
from guardian.store import connect
from tests.agent_support import sample_findings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = tmp_path / "g.db"
    monkeypatch.setattr("guardian.store.jail", lambda p: db)
    work = tmp_path / "work"
    work.mkdir()
    workspace.git(work, "init", "-q", "-b", "base")
    (work / "package.json").write_text('{"dependencies": {"lodash": "^4.17.0"}}\n')
    (work / "package-lock.json").write_text("{}\n")
    workspace.git(work, "add", "-A")
    workspace.git(work, "commit", "-q", "-m", "base")
    workspace.git(work, "checkout", "-q", "-b", "guardian/fix-f-001")
    (work / "package.json").write_text('{"dependencies": {"lodash": "^4.17.21"}}\n')
    (work / "package-lock.json").write_text('{"lockfileVersion": 3}\n')
    out = tmp_path / "out"
    monkeypatch.setattr(export, "jail", lambda p: work if str(p) == str(work) else out / "x")
    monkeypatch.setattr(export, "WORKSPACE", tmp_path)
    monkeypatch.setattr(export.service, "run_target", lambda c, r: "t")
    monkeypatch.setattr(
        export, "load_target", lambda n: {"repo": "https://github.com/me/app", "commit": "a" * 40}
    )
    fs, _ = sample_findings()
    conn = connect("x.db")
    p = add_proposal(
        conn, propose(fs, "F-001", {"dependencies": {"lodash": "^4.17.0"}}, run_id="run1"), "t"
    )
    yield conn, p, work, out
    conn.close()


def validated(conn, p, work, verdict="verified"):
    add_validation(conn, "run1", p.id, {"verdict": verdict, "branch": {"path": str(work)}})


def test_needs_human_approval(env):
    conn, p, work, _ = env
    validated(conn, p, work)
    with pytest.raises(ApprovalError, match="not been approved"):
        export.export_fix("x.db", "run1", p.id)


def test_needs_a_good_verdict(env):
    conn, p, work, _ = env
    decide(conn, "run1", p.id, "approved", "Human")
    validated(conn, p, work, "failed")
    with pytest.raises(ApprovalError, match="verified"):
        export.export_fix("x.db", "run1", p.id)


def test_patch_and_metadata(env, tmp_path):
    conn, p, work, out = env
    decide(conn, "run1", p.id, "approved", "Human")
    validated(conn, p, work)
    (out / "x").mkdir(parents=True)
    res = export.export_fix("x.db", "run1", p.id)
    patch = (out / "x" / f"{p.id}.patch").read_text()
    assert "^4.17.21" in patch and "lockfileVersion" in patch
    meta = json.loads((out / "x" / f"{p.id}.json").read_text())
    assert meta["patch_sha256"] == hashlib.sha256(patch.encode()).hexdigest()
    assert meta["approved_by"] == "Human" and meta["branch"].startswith("guardian/fix-")
    assert res["command"].startswith("scripts/push_fix.sh ")


def test_push_script_refuses_a_changed_patch(env, tmp_path):
    conn, p, work, out = env
    decide(conn, "run1", p.id, "approved", "Human")
    validated(conn, p, work)
    (out / "x").mkdir(parents=True)
    export.export_fix("x.db", "run1", p.id)
    (out / "x" / f"{p.id}.patch").write_text("tampered\n")
    done = subprocess.run(  # noqa: S603
        [str(ROOT / "scripts" / "push_fix.sh"), str(out / "x" / f"{p.id}.json")],
        capture_output=True, text=True, input="", check=False,
    )  # fmt: skip
    assert done.returncode == 2 and "hash mismatch" in done.stderr


