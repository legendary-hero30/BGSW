"""Opt-in live test: real agents, real model (DeepSeek on DeepInfra), real scanners.

It costs money and takes several minutes, so it runs only when BOTH are set:
    GUARDIAN_LIVE_TESTS=1  DEEPINFRA_API_KEY=...  GUARDIAN_ALLOW_EXTERNAL_MODELS=1
The assertions are structural invariants. Agent behavior is not deterministic, so nothing here
depends on what the agents decide, only on the guarantees the system makes about any run.
"""

import json
import os
import shutil

import pytest

from guardian.agents.budget import BudgetLimits
from guardian.agents.ledger import Ledger
from guardian.agents.runner import run_goal
from guardian.scan.verify import verify_run
from guardian.tools.runner import WORKSPACE

LIVE = (
    all(os.environ.get(k) for k in ("GUARDIAN_LIVE_TESTS", "DEEPINFRA_API_KEY"))
    and os.environ.get("GUARDIAN_ALLOW_EXTERNAL_MODELS") == "1"
)
READY = (WORKSPACE / "targets" / "nodegoat" / "package-lock.json").exists() and (
    WORKSPACE / "tools" / "bin" / "grype"
).exists()

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE, reason="set GUARDIAN_LIVE_TESTS=1 and the DeepInfra key to run"),
    pytest.mark.skipif(not READY, reason="NodeGoat checkout or pinned scanners missing"),
]


def test_a_real_goal_driven_run_keeps_every_guarantee():
    out, db = "runs/pytest-live", "runs/pytest-live.db"
    shutil.rmtree(WORKSPACE / out, ignore_errors=True)
    (WORKSPACE / db).unlink(missing_ok=True)
    limits = BudgetLimits(max_steps=100, max_tool_calls=250, max_seconds=900, max_tokens=1_200_000)
    doc = run_goal("nodegoat", out_dir=out, db=db, limits=limits, sandbox="none")

    assert doc["status"] in {"completed", "incomplete", "budget_exhausted"}
    usage = doc["usage"]
    assert usage["steps"] <= limits.max_steps and usage["tool_calls"] <= limits.max_tool_calls
    assert doc["blocked_tool_calls"] == []  # agents only used tools on their roster
    assert doc["plan"], "the supervisor planned"
    assert (WORKSPACE / out / "agent-report.md").exists()  # a report always exists (maybe partial)

    ledger = Ledger(db, doc["agent_run_id"])
    events = ledger.events()
    kinds = {e["kind"] for e in events}
    assert {"model_call", "model_response", "tool_call"} <= kinds
    assert any(e["kind"] == "delegate_start" for e in events), "work was delegated"
    assert ledger.run_info()["status"] == doc["status"]
    ledger.close()

    if doc["run_id"]:  # findings were built: every cited fact must resolve
        assert verify_run(out).failures == []
    if doc["report_accepted"]:
        report = (WORKSPACE / out / "agent-report.md").read_text()
        assert "Run facts (deterministic" in report
        assert not [h for h in doc["hypotheses"] if h["status"] == "proposed"]
    json.loads((WORKSPACE / out / "agent-run.json").read_text())
