"""Validation logic: diffs, verdict rules, the isolated work copy, and the approval refusal."""

import json

import pytest

from guardian.remediation import validate as v
from guardian.remediation import workspace
from guardian.remediation.engine import propose
from guardian.remediation.proposals import ApprovalError, add_proposal
from guardian.schemas import FindingSet
from guardian.store import connect
from tests.agent_support import DB, OUT, TARGET, build_session, cleanup, sample_findings

MANIFEST = {"name": "app", "dependencies": {"lodash": "^4.17.0", "evil": "^1"}}
STEPS_NOT_RUN = {"build": {"status": "not_run"}, "tests": {"status": "not_run"}}
STEPS_OK = {"build": {"status": "passed"}, "tests": {"status": "passed"}}
NO_SBOM = {"added": [], "removed": [], "version_changed": []}


@pytest.fixture
def fs():
    return sample_findings()[0]


def prop(fs):
    return propose(fs, "F-001", MANIFEST, run_id="r")


def without(fs, *ids) -> FindingSet:
    return FindingSet(
        evidence=fs.evidence, findings=tuple(f for f in fs.findings if f.id not in ids)
    )


def test_resolved_finding_is_detected(fs):
    d = v.findings_diff(fs, without(fs, "F-001"), prop(fs))
    assert d["targeted_resolved"] == ["F-001"] and not d["targeted_remaining"] and not d["new"]


def test_unchanged_finding_is_remaining(fs):
    d = v.findings_diff(fs, fs, prop(fs))
    assert d["targeted_remaining"] == ["F-001"]
    assert v.verdict_for(d, STEPS_NOT_RUN, NO_SBOM, prop(fs))[0] == "failed"


def test_new_finding_is_reported(fs):
    after = without(fs, "F-001")
    extra = fs.findings[0].model_copy(
        update={
            "id": "F-009",
            "advisory_ids": ("CVE-2099-1",),
            "component": fs.findings[1].component,
        }
    )
    after = FindingSet(evidence=after.evidence, findings=(*after.findings, extra))
    d = v.findings_diff(fs, after, prop(fs))
    assert [f["id"] for f in d["new"]] == ["F-009"]
    assert v.verdict_for(d, STEPS_NOT_RUN, NO_SBOM, prop(fs))[0] == "failed"  # new High/Critical


def test_verified_only_when_build_and_tests_passed(fs):
    d = v.findings_diff(fs, without(fs, "F-001"), prop(fs))
    assert v.verdict_for(d, STEPS_NOT_RUN, NO_SBOM, prop(fs))[0] == "partially_verified"
    assert v.verdict_for(d, STEPS_OK, NO_SBOM, prop(fs))[0] == "verified"
    failed = {"build": {"status": "failed"}, "tests": {"status": "passed"}}
    assert v.verdict_for(d, failed, NO_SBOM, prop(fs))[0] == "failed"


def test_unexplained_sbom_change_blocks_verified(fs):
    d = v.findings_diff(fs, without(fs, "F-001"), prop(fs))
    sbom = {"added": ["surprise@1.0.0"], "removed": [], "version_changed": []}
    assert v.verdict_for(d, STEPS_OK, sbom, prop(fs))[0] == "partially_verified"


def test_sbom_diff(tmp_path):
    def doc(*cs):
        return {
            "components": [
                {"name": n, "version": ver, "purl": f"pkg:npm/{n}@{ver}"} for n, ver in cs
            ]
        }

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(doc(("lodash", "4.17.15"), ("x", "1.0.0"))))
    b.write_text(json.dumps(doc(("lodash", "4.17.21"), ("y", "2.0.0"))))
    d = v.sbom_diff(a, b)
    assert d["version_changed"] == ["lodash"]
    assert d["added"] == ["lodash@4.17.21", "y@2.0.0"] and d["removed"] == [
        "lodash@4.17.15",
        "x@1.0.0",
    ]


def test_workspace_applies_edit_on_a_branch_and_leaves_original_alone(monkeypatch, tmp_path):
    session = build_session(monkeypatch)
    repo = session.pipeline.root
    (repo / "package.json").write_text(json.dumps(MANIFEST, indent=2) + "\n")
    monkeypatch.setattr("guardian.remediation.workspace.WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(
        "guardian.remediation.workspace.load_target",
        lambda n: dict(TARGET),
    )
    monkeypatch.setattr("guardian.remediation.workspace.WORKSPACE", tmp_path)
    monkeypatch.setattr("guardian.remediation.workspace._register", lambda t: None)
    original = (repo / "package.json").read_text()
    try:
        fs = sample_findings()[0]
        p = prop(fs)
        monkeypatch.setattr("guardian.remediation.workspace.jail", lambda path: repo)
        res = workspace.create("fixture", p)
        assert res["branch"] == "guardian/fix-F-001"
        assert '"^4.17.21"' in res["diff"] and "-" in res["diff"]
        assert (repo / "package.json").read_text() == original
    finally:
        cleanup()


def test_edit_refuses_a_stale_manifest():
    fs = sample_findings()[0]
    p = prop(fs)
    with pytest.raises(workspace.WorkspaceError, match="expected"):
        workspace.apply_edit({"dependencies": {"lodash": "^3.0.0"}}, p.edits[0])


def test_validate_refuses_unapproved(monkeypatch):
    session = build_session(monkeypatch)
    try:
        conn = connect(DB)
        p = add_proposal(
            conn,
            prop(sample_findings()[0]).model_copy(update={"run_id": session.pipeline.run_id}),
            "t",
        )
        conn.close()
        with pytest.raises(ApprovalError):
            v.validate(DB, session.pipeline.run_id, p.id, "fixture", OUT)
    finally:
        cleanup()


def test_path_named_findings_do_not_change_identity_between_copies(fs):
    """A Dockerfile finding is named by its path; the work copy has a different directory."""

    def renamed(name: str) -> FindingSet:
        first = fs.findings[0]
        moved = first.model_copy(
            update={"component": first.component.model_copy(update={"name": name})}
        )
        return FindingSet(evidence=fs.evidence, findings=(moved, *fs.findings[1:]))

    before = renamed("targets/dynamic/app-1/Dockerfile")
    after = renamed("targets/work/app-1-r-001/Dockerfile")
    d = v.findings_diff(before, after, prop(fs))
    assert d["new"] == [] and len(d["resolved"]) == 0


def test_report_keeps_the_steps_taken_after_approval(monkeypatch):
    from guardian.remediation.proposals import decide

    session = build_session(monkeypatch)
    try:
        conn = connect(DB)
        p = add_proposal(
            conn,
            prop(sample_findings()[0]).model_copy(update={"run_id": session.pipeline.run_id}),
            "t",
        )
        decide(conn, session.pipeline.run_id, p.id, "approved", "Human")
        conn.close()

        def boom(*a, **k):
            raise workspace.WorkspaceError("no copy")

        monkeypatch.setattr(workspace, "create", boom)
        seen: list[str] = []
        report = v.validate(
            DB, session.pipeline.run_id, p.id, "fixture", OUT, on_step=seen.append
        )
        assert report["verdict"] == "blocked"
        msgs = [s["msg"] for s in report["progress"]]
        assert msgs == seen and "Approval confirmed: Human approved" in msgs[0]
        assert all("at" in s for s in report["progress"])
    finally:
        cleanup()
