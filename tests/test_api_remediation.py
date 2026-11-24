"""The approval gate over HTTP: token, loopback Host, named approver, validate after approval."""

import json
import shutil

import pytest
from fastapi.testclient import TestClient

from guardian.api.app import create_app
from guardian.remediation.engine import propose
from guardian.remediation.proposals import add_proposal
from guardian.store import connect, save_run
from guardian.tools.runner import WORKSPACE
from tests.agent_support import sample_findings

DIR = WORKSPACE / "runs" / "pytest-apirem"
DB = "runs/pytest-apirem/guardian.db"
RUN = "runs/pytest-apirem/run"
MANIFEST = {"dependencies": {"lodash": "^4.17.0"}}


@pytest.fixture(scope="module")
def client():
    shutil.rmtree(DIR, ignore_errors=True)
    (DIR / "ui" / "assets").mkdir(parents=True)
    (DIR / "ui" / "index.html").write_text("<!doctype html>")
    fs, graph = sample_findings()
    conn = connect(DB)
    summary = {
        "target": {"name": "fixture", "commit": "c" * 40},
        "generated_at": "2026-11-24T00:00:00",
        "findings": 3,
    }
    save_run(conn, RUN, summary, fs, graph)
    add_proposal(conn, propose(fs, "F-001", MANIFEST, run_id=RUN), "test")
    add_proposal(conn, propose(fs, "F-002", MANIFEST, run_id=RUN), "test")
    conn.close()
    app = create_app(DB, DIR / "ui", job_runner=lambda *a: None)
    with TestClient(app, base_url="http://localhost") as c:
        yield c
    shutil.rmtree(DIR, ignore_errors=True)


def token(client) -> dict:
    return {"X-Guardian-Approval": client.get("/api/approval-token").json()["token"]}


def test_proposals_are_listed_and_unapproved(client):
    rows = client.get("/api/proposals", params={"run": RUN}).json()["proposals"]
    assert [r["id"] for r in rows] == ["R-001", "R-002"]
    assert rows[0]["status"] == "proposed" and rows[0]["approvals"] == []
    full = client.get("/api/proposals/R-001", params={"run": RUN}).json()
    assert full["edits"][0]["to_spec"] == "^4.17.21" and full["rollback"]


def test_approval_needs_the_token(client):
    body = {"run": RUN, "approver": "alice"}
    assert client.post("/api/proposals/R-001/approve", json=body).status_code == 403
    bad = {"X-Guardian-Approval": "nope"}
    assert client.post("/api/proposals/R-001/approve", json=body, headers=bad).status_code == 403


def test_non_loopback_host_and_foreign_origin_are_refused(client):
    h = token(client)
    body = {"run": RUN, "approver": "alice"}
    r = client.post("/api/proposals/R-001/approve", json=body, headers={**h, "Host": "evil.test"})
    assert r.status_code == 403
    r = client.post(
        "/api/proposals/R-001/approve", json=body, headers={**h, "Origin": "http://evil.test"}
    )
    assert r.status_code == 403
    assert client.get("/api/approval-token", headers={"Host": "evil.test"}).status_code == 403


def test_validate_before_approval_is_refused(client):
    r = client.post("/api/proposals/R-001/validate", json={"run": RUN}, headers=token(client))
    assert r.status_code == 409 and "not been approved" in r.json()["detail"]


def test_non_applicable_proposal_cannot_be_approved(client):
    r = client.post(
        "/api/proposals/R-002/approve", json={"run": RUN, "approver": "a"}, headers=token(client)
    )
    assert r.status_code == 409


def test_approval_is_logged_with_approver_and_time(client):
    body = {"run": RUN, "approver": "alice", "note": "ok"}
    r = client.post("/api/proposals/R-001/approve", json=body, headers=token(client))
    assert r.status_code == 200
    rec = r.json()
    assert rec["approver"] == "alice" and rec["at"] and len(rec["proposal_sha"]) == 64
    after = client.get("/api/proposals/R-001", params={"run": RUN}).json()
    assert after["status"] == "approved" and after["approvals"][0]["note"] == "ok"


def test_unknown_run_and_malformed_ids(client):
    assert client.get("/api/proposals", params={"run": "nope"}).json()["proposals"] == []
    assert client.get("/api/proposals/../x", params={"run": RUN}).status_code in {404, 422}
    assert client.post("/api/proposals/R-1/approve", json={}).status_code == 405
    assert json.dumps(client.get("/api/proposals", params={"run": RUN}).json())


def test_concurrent_reads_do_not_share_a_connection(client):
    from concurrent.futures import ThreadPoolExecutor

    def hit(_):
        return client.get("/api/findings", params={"run": RUN, "limit": 5}).status_code

    with ThreadPoolExecutor(8) as ex:
        assert set(ex.map(hit, range(80))) == {200}


def test_capabilities_report_what_is_missing(client, monkeypatch):
    monkeypatch.delenv("DEEPINFRA_API_KEY", raising=False)
    monkeypatch.delenv("GUARDIAN_ALLOW_REGISTRY_ACCESS", raising=False)
    caps = client.get("/api/capabilities").json()
    assert caps["agents"]["ready"] is False and "DEEPINFRA_API_KEY" in caps["agents"]["detail"]
    assert caps["validation"]["ready"] is False and "REGISTRY" in caps["validation"]["detail"]
    assert set(caps) == {"agents", "validation", "sandbox", "push"}


def test_start_run_accepts_demo_and_goal(client):
    assert client.post("/api/runs", json={}).status_code == 422
    r = client.post("/api/runs", json={"demo": True, "goal": "assess"})
    assert r.status_code == 202 and r.json()["repo"] == "bundled demo app"
    assert client.post("/api/runs", json={"demo": True, "goal": "nope"}).status_code == 422
