"""The deterministic grounding gate. No model: it validates text against stored facts."""

import pytest

from guardian.agents.gate import (
    ADVISORY_RE,
    PKG_VERSION_RE,
    VERSION_RE,
    facts_for,
    gate,
    grounding_problems,
)
from tests.agent_support import sample_findings

FS, _ = sample_findings()
FINDINGS = {f.id: f for f in FS.findings}
EVIDENCE = {r.id: r for r in FS.evidence}


def good(**overrides) -> dict:
    base = {
        "finding_id": "F-001",
        "why_it_matters": "Pollution bug in lodash@4.17.15 (CVE-2020-0001), fixed in 4.17.21.",
        "reachability": "The app imported this exact copy; exposure is network facing.",
        "confidence": "high",
        "confidence_reason": "two scanners agree, CVSS 9.8",
        "cited_evidence": ["E-001", "E-002"],
    }
    return {**base, **overrides}


def test_accepts_grounded_explanation():
    exp, reasons = gate(good(), FINDINGS, EVIDENCE)
    assert reasons == [] and exp is not None
    assert exp.rationale().endswith("[E-001] [E-002]")


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"cited_evidence": ["E-003"]}, "E-003, which is not evidence"),
        ({"why_it_matters": "See E-003 for the proof of this lodash@4.17.15 issue."}, "E-003"),
        (
            {"why_it_matters": "Also tracked as CVE-2099-0001 in lodash@4.17.15 today."},
            "CVE-2099-0001",
        ),
        (
            {"why_it_matters": "Invented GHSA-zzzz-zzzz-zzzz affects lodash@4.17.15 too."},
            "GHSA-ZZZZ",
        ),
        (
            {"why_it_matters": "It comes from express@4.16.0 via lodash@4.17.15 here."},
            "express@4.16.0",
        ),
        (
            {"why_it_matters": "Upgrade lodash@4.17.15 to 4.17.99 to remove the issue now."},
            "4.17.99",
        ),
        ({"reachability": "It is reachable from the server and network facing."}, "imported"),
        ({"finding_id": "F-999"}, "unknown finding"),
        ({"confidence": "certain"}, "schema"),
        ({"cited_evidence": []}, "schema"),
    ],
)
def test_rejects(override, reason):
    exp, reasons = gate(good(**override), FINDINGS, EVIDENCE)
    assert exp is None
    assert any(reason in r for r in reasons), reasons


def test_decimals_are_not_versions_and_fix_versions_are_allowed():
    text = "EPSS 0.5 and CVSS 9.8 for lodash@4.17.15; the fixed version 4.17.21 was reported."
    assert gate(good(why_it_matters=text), FINDINGS, EVIDENCE)[1] == []


# --- a version or package at the end of a sentence (live-run regression) -------------------------


def test_sentence_final_package_version_is_parsed_without_the_period():
    assert PKG_VERSION_RE.findall("It affects lodash@4.17.15. Next sentence.") == [
        ("lodash", "4.17.15")
    ]
    assert PKG_VERSION_RE.findall("via nodemon@1.19.1.") == [("nodemon", "1.19.1")]
    assert PKG_VERSION_RE.findall("pre@1.0.0-beta.1, ok") == [("pre", "1.0.0-beta.1")]


def test_sentence_final_version_is_still_checked():
    assert VERSION_RE.findall("fixed in 4.17.21.") == ["4.17.21"]
    assert VERSION_RE.findall("a 1.2.3.4 build") == []  # four-part: not a semver
    ok = gate(good(why_it_matters="Prototype pollution in lodash@4.17.15, fixed in 4.17.21."),
              FINDINGS, EVIDENCE)  # fmt: skip
    assert ok[1] == []
    bad = gate(good(why_it_matters="Prototype pollution in lodash@4.17.15, fixed in 9.9.9."),
               FINDINGS, EVIDENCE)  # fmt: skip
    assert bad[0] is None and any("9.9.9" in r for r in bad[1])  # this used to slip through


def test_sentence_final_package_matches_the_path():
    text = "The exposure reaches the app through lodash@4.17.15."
    assert gate(good(why_it_matters=text), FINDINGS, EVIDENCE)[1] == []


# --- versions that tools reported in titles and evidence excerpts --------------------------------


def test_versions_in_titles_and_excerpts_are_tool_reported_facts():
    f = FINDINGS["F-003"]
    text = "The base image runs alpine 3.15.4, which no longer gets security updates."
    with_evidence = facts_for([f], scope="F-003", evidence=EVIDENCE)
    without = facts_for([f], scope="F-003")
    assert "3.15.4" in with_evidence.versions  # from the title and the Trivy excerpt
    assert grounding_problems(text, with_evidence) == []
    # (the title alone also carries it)
    assert "3.15.4" in without.versions
    invented = grounding_problems("It runs alpine 3.99.9 today.", with_evidence)
    assert any("3.99.9" in p for p in invented)


def test_excerpt_versions_need_the_evidence_map():
    f = FINDINGS["F-003"]
    stripped = f.model_copy(update={"title": "node@12-alpine: base image is end of life"})
    assert "3.15.4" not in facts_for([stripped], scope="x").versions
    assert "3.15.4" in facts_for([stripped], scope="x", evidence=EVIDENCE).versions


def test_scopes_cover_several_findings_and_the_whole_run():
    both = facts_for([FINDINGS["F-001"], FINDINGS["F-002"]], scope="F-001/F-002")
    assert {"E-001", "E-003"} <= both.evidence_ids
    assert "E-004" not in both.evidence_ids
    problems = grounding_problems("cites E-004 and GHSA-dddd-eeee-ffff", both)
    assert problems == ["cites E-004, which is not evidence of F-001/F-002"]
    run = facts_for(FS.findings, scope="the run", extra_labels=["express@4.16.4"])
    assert grounding_problems("express@4.16.4 and E-004 and 4.16.4", run) == []


def test_advisory_pattern_is_deliberately_broad():
    assert ADVISORY_RE.findall("GHSA-zzzz-zzzz-zzzz CVE-2020-1234 MAL-2023-462") == [
        "GHSA-zzzz-zzzz-zzzz", "CVE-2020-1234", "MAL-2023-462",
    ]  # fmt: skip
