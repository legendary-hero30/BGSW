"""Agent middleware (budget, allow-list, step limits, audit trail) and the supervisor wiring."""

import importlib.util
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from guardian.agents.budget import BudgetExhausted, BudgetLimits, BudgetTracker
from guardian.agents.runtime import AgentRuntime
from guardian.agents.supervisor import (
    SPECIALISTS,
    STEP_LIMITS,
    build_supervisor,
    load_prompts,
    prompt_versions,
)
from guardian.agents.toolkit import ROSTER_TOOLS
from tests.agent_support import build_session, cleanup


@pytest.fixture
def S(monkeypatch):  # noqa: N802
    session = build_session(monkeypatch, built=False)
    yield session
    session.ledger.close()
    cleanup()


def runtime(session, allowed=("read_repo_file", "task"), limit=4, supervisor=False):
    blocked: list[str] = []
    mw = AgentRuntime(
        session, "risk", frozenset(allowed), blocked, warns_on_budget=supervisor, step_limit=limit
    )
    return mw, blocked


def ai(n=1, **kw):
    return [AIMessage(content=f"step {i}", **kw) for i in range(n)]


def request(name="read_repo_file", args=None, call_id="c1"):
    return SimpleNamespace(tool_call={"name": name, "args": args or {}, "id": call_id})


# --- model calls -----------------------------------------------------------------------------


def test_before_model_counts_steps_and_logs_the_prompt_digest(S):
    mw, _ = runtime(S)
    assert mw.before_model({"messages": [HumanMessage(content="hi")]}, None) is None
    assert S.budget.steps == 1
    event = S.ledger.events(("model_call",))[0]
    assert event["agent"] == "risk" and event["payload"]["used"] == 0
    assert len(event["payload"]["prompt_digest"]) == 16


def test_step_limit_ends_the_invocation_with_an_honest_note(S):
    mw, _ = runtime(S, limit=3)
    update = mw.before_model({"messages": ai(3)}, None)
    assert update["jump_to"] == "end"
    assert "reached its limit of 3" in update["messages"][0].content
    assert "incomplete" in update["messages"][0].content
    assert S.budget.steps == 0  # a stopped call is not a model call
    assert S.ledger.events(("step_limit",))[0]["payload"] == {"limit": 3}
    assert getattr(AgentRuntime.before_model, "__can_jump_to__", None) == ["end"]


def test_step_limit_notice_two_calls_before_the_end(S):
    mw, _ = runtime(S, limit=5)
    update = mw.before_model({"messages": ai(3)}, None)
    assert "STEP LIMIT NOTICE" in update["messages"][0].content and "jump_to" not in update
    assert mw.before_model({"messages": ai(2)}, None) is None


def test_step_limit_is_counted_per_conversation_not_per_middleware(S):
    """Parallel invocations of one specialist share a middleware instance."""
    mw, _ = runtime(S, limit=5)
    assert mw.before_model({"messages": ai(5)}, None)["jump_to"] == "end"
    assert mw.before_model({"messages": ai(1)}, None) is None  # a fresh invocation is unaffected


def test_supervisor_gets_a_budget_notice_once(S):
    S.budget = BudgetTracker(BudgetLimits(max_steps=10))
    mw, _ = runtime(S, limit=50, supervisor=True)
    notices = []
    for _ in range(9):
        update = mw.before_model({"messages": [HumanMessage(content="x")]}, None)
        if update:
            notices.append(update["messages"][0].content)
    assert len(notices) == 1 and notices[0].startswith("BUDGET NOTICE")
    assert S.ledger.events(("budget_notice",))


def test_exhausted_budget_stops_the_next_model_call(S):
    S.budget = BudgetTracker(BudgetLimits(max_steps=1))
    mw, _ = runtime(S)
    mw.before_model({"messages": []}, None)
    with pytest.raises(BudgetExhausted):
        mw.before_model({"messages": []}, None)


def test_after_model_records_tokens_text_and_calls_redacted(S):
    mw, _ = runtime(S)
    secret = "ghp_" + "a" * 36
    msg = AIMessage(
        content=f"found {secret}",
        tool_calls=[{"name": "read_repo_file", "args": {"path": "a.js"}, "id": "1"}],
        usage_metadata={"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
    )
    mw.after_model({"messages": [msg]}, None)
    assert (S.budget.tokens_in, S.budget.tokens_out) == (120, 30)
    payload = S.ledger.events(("model_response",))[0]["payload"]
    assert secret not in str(payload) and payload["tool_calls"][0]["name"] == "read_repo_file"


def test_after_model_without_usage_is_counted_as_unknown(S):
    mw, _ = runtime(S)
    mw.after_model({"messages": [AIMessage(content="no usage reported")]}, None)
    assert S.budget.snapshot()["unknown_usage_calls"] == 1 and S.budget.tokens == 0


# --- tool calls -----------------------------------------------------------------------------


def test_tools_outside_the_roster_are_blocked_and_recorded(S):
    mw, blocked = runtime(S)
    result = mw.wrap_tool_call(request("write_file"), lambda r: pytest.fail("must not run"))
    assert isinstance(result, ToolMessage) and result.status == "error"
    assert "not available to risk" in result.content
    assert blocked == ["risk:write_file"]
    assert S.ledger.events(("blocked",))[0]["name"] == "write_file"
    assert S.budget.tool_calls == 0


def test_successful_tool_calls_are_logged_with_size_time_and_a_redacted_preview(S):
    seen = []
    S.on_event = seen.append
    mw, _ = runtime(S)
    out = ToolMessage(content='{"ok": 1, "token": "ghp_' + "b" * 36 + '"}', tool_call_id="c1")
    assert mw.wrap_tool_call(request(args={"path": "a.js"}), lambda r: out) is out
    e = S.ledger.events(("tool_call",))[0]
    assert (
        e["payload"]["result_chars"] == len(out.content) and "ghp_" not in e["payload"]["preview"]
    )
    assert e["payload"]["args"] == {"path": "a.js"} and e["payload"]["error"] is False
    assert seen == [
        {"agent": "risk", "tool": "read_repo_file", "args": {"path": "a.js"}, "error": False}
    ]
    assert S.budget.tool_calls == 1


def test_error_results_are_flagged_so_the_ui_can_show_them(S):
    mw, _ = runtime(S)
    err = ToolMessage(content='{"error": "AgentToolError: nope"}', tool_call_id="c1")
    mw.wrap_tool_call(request(), lambda r: err)
    assert S.ledger.events(("tool_call",))[0]["payload"]["error"] is True


def test_a_crashing_tool_becomes_an_error_message_the_agent_can_read(S):
    mw, _ = runtime(S)

    def boom(_):
        raise RuntimeError("disk on fire")

    result = mw.wrap_tool_call(request(), boom)
    assert result.status == "error" and "disk on fire" in result.content
    assert S.ledger.events(("tool_error",))[0]["payload"]["error"] is True


def test_budget_exhaustion_inside_a_tool_propagates_and_is_logged(S):
    mw, _ = runtime(S)

    def spent(_):
        raise BudgetExhausted("token budget spent")

    with pytest.raises(BudgetExhausted):
        mw.wrap_tool_call(request("task", {"subagent_type": "risk"}), spent)
    assert S.ledger.events(("budget_exhausted",))


def test_budget_is_checked_before_each_tool_call(S):
    S.budget = BudgetTracker(BudgetLimits(max_tool_calls=1))
    mw, _ = runtime(S)
    out = ToolMessage(content="{}", tool_call_id="c1")
    mw.wrap_tool_call(request(), lambda r: out)
    with pytest.raises(BudgetExhausted):
        mw.wrap_tool_call(request(), lambda r: out)


def test_delegation_is_logged_as_start_and_completion(S):
    mw, _ = runtime(S)
    out = ToolMessage(content="the subagent's report", tool_call_id="c1")
    mw.wrap_tool_call(
        request("task", {"subagent_type": "risk", "description": "do it"}), lambda r: out
    )
    kinds = [(e["kind"], e["name"]) for e in S.ledger.events()]
    assert ("delegate_start", "risk") in kinds and ("delegate", "task") in kinds


# --- supervisor wiring ----------------------------------------------------------------------


def test_every_role_has_a_prompt_a_roster_and_a_step_limit():
    assert set(SPECIALISTS) == set(ROSTER_TOOLS) - {"supervisor"}
    assert set(STEP_LIMITS) == set(ROSTER_TOOLS)
    prompts = load_prompts()
    assert set(prompts) == set(ROSTER_TOOLS)
    assert all("Untrusted data" in p and "Economy" in p for p in prompts.values())
    assert set(prompt_versions()) >= {"common", "supervisor", *SPECIALISTS}


def test_the_supervisor_prompt_is_a_goal_not_a_sequence():
    text = " ".join(load_prompts()["supervisor"].lower().split())
    assert "not a procedure" in text and "guidance, not a sequence" in text
    for step_words in ("first run discovery", "then run detection", "step 1:", "step 2:"):
        assert step_words not in text


@pytest.mark.skipif(
    importlib.util.find_spec("langchain_openai") is None, reason="needs --extra llm-openai"
)
def test_the_supervisor_graph_exposes_only_its_roster(S, monkeypatch):
    from guardian.agents.models import ModelConfig, build_model

    monkeypatch.setenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", "1")
    monkeypatch.setenv("DEEPINFRA_API_KEY", "construction-only-never-sent")
    model = build_model(ModelConfig())  # a real client object; nothing is called
    agent = build_supervisor(model, S, [])
    exposed = set(agent.nodes["tools"].bound.tools_by_name)
    assert exposed == {*ROSTER_TOOLS["supervisor"], "task", "read_file"}
    assert not {"sandbox_exec", "build_findings", "scan_dependencies"} & exposed


# --- repeated failures (live-run regression: 49 doomed read_file calls) ---------------------------


def failing_turns(n, text="Error: File '/targets/x/package.json' not found"):
    out = [HumanMessage(content="go")]
    for i in range(n):
        out += [
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": str(i)}]),
            ToolMessage(content=text, tool_call_id=str(i)),
        ]
    return out


def test_trailing_failures_counts_only_the_unbroken_run_at_the_end():
    from guardian.agents.runtime import _trailing_failures

    assert _trailing_failures(failing_turns(3)) == 3
    ok = ToolMessage(content='{"ok": 1}', tool_call_id="z")
    assert _trailing_failures([*failing_turns(3), ok]) == 0
    assert _trailing_failures([ok, *failing_turns(2)[1:]]) == 2  # stops at the earlier success
    assert _trailing_failures(failing_turns(2, text='{"error": "AgentToolError: nope"}')) == 2
    explicit = ToolMessage(content="boom", tool_call_id="e", status="error")
    assert _trailing_failures([HumanMessage(content="x"), explicit]) == 1


def test_four_failures_in_a_row_get_a_notice_and_a_success_resets_it(S):
    mw, _ = runtime(S, limit=50)
    assert mw.before_model({"messages": failing_turns(3)}, None) is None
    update = mw.before_model({"messages": failing_turns(4)}, None)
    assert "REPEATED ERRORS NOTICE" in update["messages"][0].content
    assert "last 4 tool calls" in update["messages"][0].content
    assert S.ledger.events(("repeated_failures",))[0]["payload"] == {"count": 4}
    recovered = [*failing_turns(4), ToolMessage(content='{"ok": 1}', tool_call_id="ok")]
    assert mw.before_model({"messages": recovered}, None) is None


def test_the_risk_agent_can_read_the_repository_the_roster_gap_behind_those_calls():
    assert "read_repo_file" in ROSTER_TOOLS["risk"]


@pytest.mark.skipif(
    importlib.util.find_spec("langchain_openai") is None, reason="needs --extra llm-openai"
)
def test_the_builtin_read_file_says_it_cannot_read_the_repository(S, monkeypatch):
    from guardian.agents.models import ModelConfig, build_model

    monkeypatch.setenv("GUARDIAN_ALLOW_EXTERNAL_MODELS", "1")
    monkeypatch.setenv("DEEPINFRA_API_KEY", "construction-only-never-sent")
    agent = build_supervisor(build_model(ModelConfig()), S, [])
    description = agent.nodes["tools"].bound.tools_by_name["read_file"].description
    assert "ONLY" in description and "read_repo_file" in description
