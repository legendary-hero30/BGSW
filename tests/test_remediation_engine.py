"""Deterministic remediation proposals: versions come only from tool-reported fixes."""

import pytest

from guardian.remediation.engine import lowest_fix, new_spec, propose
from guardian.remediation.schemas import ActionKind
from guardian.remediation.semver import change_kind, parse
from guardian.scoring.confidence import finding_confidence
from tests.agent_support import sample_findings

MANIFEST = {"dependencies": {"lodash": "^4.17.0"}}


def test_semver_basics():
    assert parse("4.17.15") < parse("4.17.21")
    assert change_kind(parse("4.17.15"), parse("4.17.21")) == "patch"
    assert change_kind(parse("1.9.1"), parse("2.0.0")) == "major"


def test_lowest_fix_prefers_same_major():
    cur = parse("1.0.0")
    fixes = [parse("2.0.0"), parse("1.2.0"), parse("1.1.0")]
    assert str(lowest_fix(cur, sorted(fixes))) == "1.1.0"
    assert lowest_fix(cur, [parse("0.9.0")]) is None


def test_new_spec_keeps_prefix():
    assert new_spec("^4.17.0", parse("4.17.21")) == "^4.17.21"
    assert new_spec("4.17.0", parse("4.17.21")) == "4.17.21"


def test_direct_upgrade_edits_dependency():
    fs, _ = sample_findings()
    p = propose(fs, "F-001", MANIFEST, run_id="r")
    assert p.action is ActionKind.UPGRADE and p.target == "4.17.21" and p.applicable
    assert p.edits[0].op == "set_dependency" and p.edits[0].to_spec == "^4.17.21"
    assert p.rollback and p.evidence_refs == ("E-001", "E-002")
    assert p.expected_risk_reduction.findings_resolved == ("F-001",)


def test_no_fix_version_means_escalate_not_a_guess():
    fs, _ = sample_findings()
    p = propose(fs, "F-002", MANIFEST, run_id="r")
    assert p.action is ActionKind.ESCALATE and p.target is None and not p.edits


def test_image_finding_needs_a_digest_and_is_not_applicable():
    fs, _ = sample_findings()
    p = propose(fs, "F-003", MANIFEST, run_id="r")
    assert p.action is ActionKind.UPDATE_BASE_IMAGE and not p.applicable and p.needs


def test_unknown_finding_raises():
    fs, _ = sample_findings()
    with pytest.raises(KeyError):
        propose(fs, "F-999", MANIFEST, run_id="r")


def test_confidence_levels_and_reasons():
    fs, _ = sample_findings()
    level, reasons = finding_confidence(fs.findings[0])
    assert level in {"high", "medium"} and reasons
    low, _ = finding_confidence(fs.findings[2])
    assert low == "low"


def test_compare_lockfiles_reports_provenance_signals():
    from guardian.remediation.compare import compare_lockfiles
    from guardian.sbom.npm_lock import LockEntry

    def e(name, ver, **kw):
        return LockEntry(path=f"node_modules/{name}", name=name, version=ver, **kw)

    reg = "https://registry.npmjs.org/"
    base = {
        "node_modules/a": e("a", "1.0.0", resolved=reg + "a", integrity="sha512-x"),
        "node_modules/b": e("b", "1.0.0", resolved=reg + "b", integrity="sha512-y"),
    }
    head = {
        "node_modules/a": e("a", "1.0.0", resolved=reg + "a", integrity="sha512-CHANGED"),
        "node_modules/c": e(
            "c", "1.0.0", resolved="https://evil.test/c.tgz", has_install_script=True
        ),
    }
    d = compare_lockfiles(base, head)
    assert d["added"] == ["c"] and d["removed"] == ["b"]
    assert d["provenance_signals"][0]["package"] == "a"
    assert "integrity hash changed with the same version" in d["provenance_signals"][0]["signals"]
    assert d["added_with_install_script"] == ["c"] and d["added_from_non_registry_host"] == ["c"]
