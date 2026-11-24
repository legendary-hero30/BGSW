"""Run lifecycle refusals and the CLI. Everything that would need a live model is refused first."""

import shutil

import pytest

from guardian import cli
from guardian.agents.budget import BudgetConfigError
from guardian.agents.ledger import Ledger
from guardian.agents.models import ModelConfig, ModelDisabledError, build_model, default_model
from guardian.agents.runner import DEFAULT_GOAL, default_out_dir, run_goal
from guardian.store import connect
from guardian.tools.runner import WORKSPACE

DIR = WORKSPACE / "runs" / "pytest-runner"
DB = "runs/pytest-runner/guardian.db"


@pytest.fixture(autouse=True)
def clean():
    shutil.rmtree(DIR, ignore_errors=True)
    yield
    shutil.rmtree(DIR, ignore_errors=True)


def agent_runs() -> int:
    conn = connect(DB)
    try:
        return conn.execute("SELECT COUNT(*) FROM agent_runs").fetchone()[0]
    finally:
        conn.close()


def test_external_models_are_refused_before_anything_is_created(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", raising=False)
    with pytest.raises(ModelDisabledError, match="GUARDIAN_ALLOW_EXTERNAL_MODELS"):
        run_goal("nodegoat", db=DB, out_dir="runs/pytest-runner/out")
    assert not (DIR / "out").exists() and agent_runs() == 0


def test_deepinfra_needs_its_own_key(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", "1")
    monkeypatch.delenv("DEEPINFRA_API_KEY", raising=False)
    with pytest.raises(ModelDisabledError, match="DEEPINFRA_API_KEY"):
        build_model(ModelConfig())


def test_unknown_provider_and_missing_package(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", "1")
    with pytest.raises(ValueError, match="unknown provider"):
        build_model(ModelConfig(provider="nope", model="x"))
    with pytest.raises(ModelDisabledError, match="not installed"):
        build_model(ModelConfig(provider="deepseek", model="x"))  # langchain_deepseek absent


def test_a_usd_budget_without_prices_is_refused_before_a_model_is_built(monkeypatch):
    monkeypatch.delenv("GUARDIAN_PRICE_IN_PER_M", raising=False)
    monkeypatch.delenv("GUARDIAN_PRICE_OUT_PER_M", raising=False)
    monkeypatch.setenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", "1")
    from guardian.agents.budget import BudgetLimits

    with pytest.raises(BudgetConfigError):
        BudgetLimits.from_env(max_usd=5)


def test_defaults():
    assert default_model("deepinfra") == "deepseek-ai/DeepSeek-V4.1-Flash-1017"
    with pytest.raises(ValueError, match="--model is required"):
        default_model("anthropic")
    assert "supply-chain risk" in DEFAULT_GOAL
    assert default_out_dir("nodegoat").startswith("runs/agent-nodegoat-")


def test_cli_run_is_refused_without_the_opt_in(monkeypatch, capsys):
    monkeypatch.delenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", raising=False)
    code = cli.main(["run", "--target", "nodegoat", "--db", DB, "--out", "runs/pytest-runner/o"])
    assert code == 2 and "refused" in capsys.readouterr().err


def test_cli_rejects_a_usd_budget_without_prices(monkeypatch, capsys):
    monkeypatch.delenv("GUARDIAN_PRICE_IN_PER_M", raising=False)
    monkeypatch.delenv("GUARDIAN_PRICE_OUT_PER_M", raising=False)
    code = cli.main(["run", "--target", "nodegoat", "--budget-usd", "5", "--db", DB])
    assert code == 2 and "prices" in capsys.readouterr().err


def test_cli_trace_and_report_read_the_ledger(capsys):
    led = Ledger(DB)
    led.start_run(
        goal="the goal", target="t", provider="deepinfra", model="m", budget={}, prompts={}
    )
    led.plan_upsert("supervisor", None, goal="scan", rationale="why")
    led.log("risk", "tool_call", "get_finding", {"preview": "a preview", "args": {}})
    run_id = led.agent_run_id
    led.close()

    assert cli.main(["trace", "--agent-run", run_id, "--db", DB]) == 0
    out = capsys.readouterr().out
    assert "the goal" in out and "get_finding" in out and "plan" in out
    assert cli.main(["trace", "--agent-run", run_id, "--db", DB, "--kinds", "plan"]) == 0
    only_plan = capsys.readouterr().out
    assert "get_finding" not in only_plan and "scan" in only_plan

    assert cli.main(["report", "--agent-run", run_id, "--db", DB]) == 1  # no accepted report yet
    assert "no accepted report" in capsys.readouterr().err
    led = Ledger(DB, run_id)
    led.save_report("# the report")
    led.close()
    assert cli.main(["report", "--agent-run", run_id, "--db", DB]) == 0
    assert capsys.readouterr().out.strip() == "# the report"


def test_cli_sandboxes_prints_both_backends(capsys):
    assert cli.main(["sandboxes"]) == 0
    assert '"docker"' in capsys.readouterr().out
