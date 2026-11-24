"""Budget, ledger (shared memory and audit trail) and secret redaction. No model involved."""

import shutil
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import pytest

from guardian.agents.budget import (
    PRICE_IN_ENV,
    PRICE_OUT_ENV,
    BudgetConfigError,
    BudgetExhausted,
    BudgetLimits,
    BudgetTracker,
)
from guardian.agents.ledger import Ledger
from guardian.redact import REDACTED, redact, redact_obj
from guardian.store import SCHEMA_VERSION, connect
from guardian.tools.runner import WORKSPACE

DIR = WORKSPACE / "runs" / "pytest-core"
DB = "runs/pytest-core/guardian.db"


@pytest.fixture
def ledger():
    shutil.rmtree(DIR, ignore_errors=True)
    led = Ledger(DB)
    led.start_run(goal="g", target="t", provider="p", model="m", budget={}, prompts={"x": "1"})
    yield led
    led.close()
    shutil.rmtree(DIR, ignore_errors=True)


# --- budget ----------------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["max_steps", "max_tool_calls", "max_seconds", "max_tokens"])
def test_limits_must_be_positive(field):
    with pytest.raises(BudgetConfigError):
        BudgetLimits(**{field: 0}).validate()


def test_usd_budget_needs_prices_and_never_assumes_them(monkeypatch):
    monkeypatch.delenv(PRICE_IN_ENV, raising=False)
    monkeypatch.delenv(PRICE_OUT_ENV, raising=False)
    with pytest.raises(BudgetConfigError, match="prices"):
        BudgetLimits.from_env(max_usd=5)
    monkeypatch.setenv(PRICE_IN_ENV, "0.2")
    monkeypatch.setenv(PRICE_OUT_ENV, "0.8")
    limits = BudgetLimits.from_env(max_usd=5)
    assert (limits.price_in_per_m, limits.price_out_per_m) == (0.2, 0.8)
    with pytest.raises(BudgetConfigError):
        BudgetLimits(max_usd=-1, price_in_per_m=1, price_out_per_m=1).validate()


def test_tracker_stops_on_each_limit():
    t = BudgetTracker(BudgetLimits(max_steps=2))
    t.start_model_call()
    t.start_model_call()
    with pytest.raises(BudgetExhausted, match="step budget"):
        t.start_model_call()
    t = BudgetTracker(BudgetLimits(max_tool_calls=1))
    t.start_tool_call()
    with pytest.raises(BudgetExhausted, match="tool-call budget"):
        t.start_tool_call()
    t = BudgetTracker(BudgetLimits(max_tokens=100))
    t.add_usage(60, 50)
    with pytest.raises(BudgetExhausted, match="token budget"):
        t.check()
    t = BudgetTracker(BudgetLimits(max_seconds=1))
    t._start -= 5
    with pytest.raises(BudgetExhausted, match="time budget"):
        t.check()


def test_spend_is_enforced_only_with_prices():
    t = BudgetTracker(BudgetLimits(max_usd=1.0, price_in_per_m=1.0, price_out_per_m=2.0))
    t.add_usage(500_000, 250_000)  # 0.5 + 0.5
    with pytest.raises(BudgetExhausted, match="spend budget"):
        t.check()
    free = BudgetTracker(BudgetLimits())
    free.add_usage(10**6, 10**6)
    assert free.usd is None and free.snapshot()["usd_enforced"] is False


def test_unknown_usage_is_counted_not_guessed():
    t = BudgetTracker(BudgetLimits())
    t.add_usage(None, None)
    assert t.tokens == 0 and t.snapshot()["unknown_usage_calls"] == 1


def test_warning_fires_once_at_80_percent():
    t = BudgetTracker(BudgetLimits(max_steps=10))
    for _ in range(7):
        t.start_model_call()
    assert t.take_warning() is None
    t.start_model_call()
    assert "BUDGET NOTICE" in t.take_warning()
    assert t.take_warning() is None


def test_exhaustion_is_sticky():
    t = BudgetTracker(BudgetLimits(max_steps=1))
    t.start_model_call()
    with pytest.raises(BudgetExhausted) as first:
        t.check()
    with pytest.raises(BudgetExhausted) as second:
        t.check()
    assert first.value.reason == second.value.reason == t.snapshot()["exhausted"]


# --- ledger: plan, atomic ids, append-only events ------------------------------------------------


def test_parallel_plan_adds_get_distinct_ids(ledger):
    """Regression: six parallel plan_add calls once all received P-02 and overwrote each other."""
    ids = []

    def add(i):
        ids.append(ledger.plan_upsert("supervisor", None, goal=f"g{i}", rationale="r")["id"])

    threads = [threading.Thread(target=add, args=(i,)) for i in range(24)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(set(ids)) == 24
    assert len(ledger.plan()) == 24


def test_parallel_hypotheses_get_distinct_ids(ledger):
    ids = []

    def add(i):
        h = ledger.hypothesis_add("risk", f"claim number {i} is long enough", "risk", ["E-001"],
                                  ["F-001"], "low")  # fmt: skip
        ids.append(h["id"])

    threads = [threading.Thread(target=add, args=(i,)) for i in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(set(ids)) == 16 == len(ledger.hypotheses())


def test_plan_revision_keeps_unchanged_fields_and_logs_every_change(ledger):
    a = ledger.plan_upsert("supervisor", None, goal="scan", rationale="why", assigned_agent="risk")
    b = ledger.plan_upsert("supervisor", a["id"], status="done")
    assert (b["goal"], b["assigned_agent"], b["status"]) == ("scan", "risk", "done")
    ops = [(e["name"], e["payload"]["status"]) for e in ledger.events(("plan",))]
    assert ops == [("add", "pending"), ("revise", "done")]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"item_id": None, "goal": "x"},  # no rationale
        {"item_id": "P-99", "status": "done"},  # unknown item
        {"item_id": None, "goal": "x", "rationale": "r", "depends_on": ["P-09"]},
        {"item_id": None, "goal": "x", "rationale": "r", "status": "bogus"},
    ],
)
def test_plan_rejects_bad_input(ledger, kwargs):
    with pytest.raises(ValueError):
        ledger.plan_upsert("supervisor", **kwargs)


def test_events_are_append_only(ledger):
    ledger.log("risk", "tool_call", "x", {"a": 1})
    raw = sqlite3.connect(WORKSPACE / DB)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("UPDATE agent_events SET kind = 'forged'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("DELETE FROM agent_events")
    raw.close()
    assert [e["kind"] for e in ledger.events()] == ["tool_call"]


def test_events_are_redacted_and_clipped(ledger):
    secret = "ghp_" + "a" * 36
    ledger.log("risk", "tool_call", "read", {"preview": f"token={secret}", "big": "x" * 10_000})
    payload = ledger.events()[0]["payload"]
    assert secret not in str(payload) and REDACTED in payload["preview"]
    assert len(payload["big"]) < 6100 and "…[+" in payload["big"]


def test_hypothesis_lifecycle_and_invalidation(ledger):
    h = ledger.hypothesis_add("risk", "a claim long enough to count", "risk", ["E-001"], ["F-001"],
                              "medium")  # fmt: skip
    assert h["status"] == "proposed"
    ledger.hypothesis_set_status("verifier", h["id"], "verified", ["supported by E-001"])
    assert ledger.hypotheses("verified")[0]["reasons"] == ["supported by E-001"]
    assert ledger.invalidate_hypotheses("risk", "ids changed") == [h["id"]]
    assert ledger.hypotheses()[0]["status"] == "needs_more_evidence"
    with pytest.raises(ValueError):
        ledger.hypothesis_set_status("verifier", "H-99", "verified", ["x"])
    with pytest.raises(ValueError):
        ledger.hypothesis_set_status("verifier", h["id"], "maybe", ["x"])


def test_count_events_by_kind_and_name(ledger):
    for fid in ("F-001", "F-001", "F-002"):
        ledger.log("risk", "gate_rejection", fid, {})
    assert ledger.count_events("gate_rejection") == 3
    assert ledger.count_events("gate_rejection", "F-001") == 2


def test_stale_runs_are_reaped_but_not_the_current_one(ledger):
    other = Ledger(DB)
    other.start_run(goal="old", target="t", provider="p", model="m", budget={}, prompts={})
    old = (datetime.now(UTC) - timedelta(hours=3)).isoformat(timespec="milliseconds")
    raw = sqlite3.connect(WORKSPACE / DB)
    raw.execute(
        "UPDATE agent_runs SET started_at = ? WHERE agent_run_id = ?", (old, other.agent_run_id)
    )
    raw.commit()
    raw.close()
    assert ledger.reap_stale() == 1
    assert other.run_info()["status"] == "interrupted"
    assert ledger.run_info()["status"] == "running"
    other.close()


def test_finish_run_records_usage_and_report(ledger):
    ledger.finish_run("completed", None, {"steps": 3}, "# Report")
    info = ledger.run_info()
    assert info["status"] == "completed" and info["usage"] == {"steps": 3}
    assert info["report_md"] == "# Report" and info["finished_at"]


def test_schema_is_v4_and_older_stores_migrate():
    shutil.rmtree(DIR, ignore_errors=True)
    DIR.mkdir(parents=True)
    raw = sqlite3.connect(WORKSPACE / "runs/pytest-core/old.db")
    raw.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    raw.execute("INSERT INTO meta VALUES ('schema_version', '1')")
    raw.commit()
    raw.close()
    conn = connect("runs/pytest-core/old.db")
    assert conn.execute("SELECT value FROM meta").fetchone()[0] == str(SCHEMA_VERSION) == "4"
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"explanations", "agent_runs", "agent_events", "plan_items", "hypotheses"} <= tables
    conn.close()
    shutil.rmtree(DIR, ignore_errors=True)


# --- redaction --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "ghp_" + "a" * 36,
        "AKIA" + "A" * 16,
        "sk-" + "b" * 30,
        "Bearer " + "c" * 30,
        "xoxb-1234567890-abcdef",
        "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3.abcdefghijk",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_known_secret_shapes_are_redacted(text):
    assert redact(f"before {text} after") == f"before {REDACTED} after"


def test_assignments_are_redacted_but_plain_text_is_not():
    assert redact("password = 'hunter2hunter2'") == f"password = {REDACTED}"
    assert redact('"api_key": "abcdef123456"') == f'"api_key": {REDACTED}'
    assert redact("DB_PASSWORD=supersecret1") == f"DB_PASSWORD={REDACTED}"
    assert redact("the token budget is spent") == "the token budget is spent"


def test_configured_api_key_value_is_redacted_everywhere(monkeypatch):
    monkeypatch.setenv("DEEPINFRA_API_KEY", "deepinfra-secret-value-123")
    assert redact("key deepinfra-secret-value-123 leaked") == f"key {REDACTED} leaked"
    assert redact_obj({"a": ["x deepinfra-secret-value-123"]}) == {"a": [f"x {REDACTED}"]}
