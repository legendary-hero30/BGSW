"""End-to-end D1.S4 baseline on NodeGoat (skipped without pinned tools, target, or caches).

The vulnerability databases change daily, so this checks properties, not exact counts.
"""

import json
import shutil

import pytest

from guardian.scan.baseline import CACHE, baseline
from guardian.scan.verify import verify_run
from guardian.tools.runner import TOOLS_BIN, WORKSPACE

READY = all(
    (
        all((TOOLS_BIN / t).exists() for t in ("syft", "grype", "trivy", "osv-scanner")),
        (WORKSPACE / "targets" / "nodegoat" / "package-lock.json").exists(),
        (CACHE / "grype").exists(),
        (CACHE / "trivy" / "db" / "metadata.json").exists(),
        (CACHE / "osv" / "osv-scalibr" / "npm" / "all.zip").exists(),
        (CACHE / "feeds" / "feeds.json").exists(),
    )
)


@pytest.mark.integration
@pytest.mark.skipif(not READY, reason="pinned tools, NodeGoat checkout or DB caches missing")
def test_nodegoat_offline_baseline():
    out = WORKSPACE / "runs" / "pytest-d1s4"
    shutil.rmtree(out, ignore_errors=True)
    s = baseline("nodegoat", out, db="runs/pytest-d1s4/guardian.db")

    assert s["unmapped"] == []
    assert s["findings"] > 100
    assert s["by_type"]["vulnerable_direct"] > 0 and s["by_type"]["vulnerable_transitive"] > 0
    assert s["groups_by_tool_count"]["3_tools"] / s["groups"] > 0.9  # strong agreement

    findings = json.loads((out / "findings.json").read_text())["findings"]
    malicious = [f for f in findings if f["type"] == "malicious_package"]
    assert [f["component"]["name"] for f in malicious] == ["fsevents"]
    assert "MAL-2023-462" in malicious[0]["advisory_ids"]
    with_paths = {"vulnerable_direct", "vulnerable_transitive", "malicious_package",
                  "vulnerable_image_package"}  # fmt: skip
    assert all(len(f["dependency_path"]) >= 2 for f in findings if f["type"] in with_paths)

    # D1.S5 posture: one image and the CI workflows were inspected.
    assert s["image"]["manifest_digest"].startswith("sha256:")
    assert s["image"]["groups_by_tool_count"].get("2_tools", 0) > 0
    by_type = s["by_type"]
    assert by_type["vulnerable_image_package"] > 0
    assert by_type["unpinned_ci"] >= 6 and by_type["untrusted_image"] >= 2
    pinned = [f for f in findings if f["advisory_ids"] == ["GR-CI-001", "unpinned-uses"]]
    assert len(pinned) == 6  # zizmor and guardian rule agree on every tag-pinned action
    assert any(f["advisory_ids"] == ["EOSL"] for f in findings)

    # D1.S7: every finding is scored; the store round-trips exactly.
    from guardian.schemas.finding import FindingSet
    from guardian.scoring import score_risk
    from guardian.store import connect, load_findings

    fs = FindingSet.model_validate_json((out / "findings.json").read_text())
    assert all(f.risk is not None and f.risk == score_risk(f.factors) for f in fs.findings)
    assert fs.findings[0].component.name == "fsevents"  # forced Critical ranks first
    assert s["by_reachability"].get("imported", 0) > 0
    conn = connect("runs/pytest-d1s4/guardian.db")
    assert load_findings(conn, s["store"]["run_id"]) == fs
    conn.close()

    run_id = s["store"]["run_id"]
    # D1.S9: the Day 1 checklist evaluated on this real run.
    from guardian.checklist import evaluate

    items = {i.n: i for i in evaluate(run_id, "runs/pytest-d1s4/guardian.db")}
    assert all(items[n].status == "pass" for n in range(1, 9)), [
        (i.n, i.evidence) for i in items.values() if i.status == "fail"
    ]
    assert items[9].status == "n/a"  # no agent run here, so no AI claims to ground
    assert items[10].status == items[11].status == "n/a"
    assert items[12].status == "pass"  # README documents setup, dependencies and tools

    v = verify_run(out)
    assert v.failures == []
    assert v.rate == 1.0
    shutil.rmtree(out, ignore_errors=True)


SEEDED_READY = READY and (WORKSPACE / "targets" / "nodegoat-seeded" / "SEEDED.md").exists()


@pytest.mark.integration
@pytest.mark.skipif(not SEEDED_READY, reason="seeded fork missing (scripts/seed_anomalies.py)")
def test_seeded_ground_truth_evaluation():
    from guardian.scan.evaluate import evaluate

    clean, seeded = (
        WORKSPACE / "runs" / "pytest-d1s6-clean",
        WORKSPACE / "runs" / "pytest-d1s6-seeded",
    )
    for out in (clean, seeded):
        shutil.rmtree(out, ignore_errors=True)
    baseline("nodegoat", clean, db=None)
    baseline("nodegoat-seeded", seeded, db=None)
    for out in (clean, seeded):
        assert verify_run(out).failures == []

    r = evaluate(seeded, clean, WORKSPACE / "targets" / "seeded-ground-truth.json")
    missed = [i["id"] for i in r["items"] if not i["detected"]]
    assert missed == []
    assert r["seeded_recall"] == "10/10" and r["real_recall"] == "4/4"
    assert r["false_positives_new"] == []
    for out in (clean, seeded):
        shutil.rmtree(out, ignore_errors=True)
