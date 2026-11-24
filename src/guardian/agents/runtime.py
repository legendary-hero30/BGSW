"""Middleware attached to every agent: budget enforcement, tool allow-list, audit trail.

It does not steer the agents. It only (1) refuses to continue once a budget is spent, (2) blocks
tools outside the agent's roster, and (3) records every model call, tool call, delegation and
error in the append-only ledger. ``BudgetExhausted`` propagates out through nested subagents
(Deep Agents re-raises tool exceptions), so the runner can stop and report what exists.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware, hook_config
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from guardian.agents.budget import BudgetExhausted
from guardian.agents.session import Session
from guardian.log import short
from guardian.redact import redact, redact_obj

log = logging.getLogger("guardian.agent")
# Tools that only read state. An identical repeated call returns the same thing, so after
# DUPLICATE_AT of them the agent is told to use what it has instead of looping.
READ_ONLY = frozenset({
    "plan_list", "budget_status", "discover_files", "read_repo_file", "search_repo", "query_graph",
    "scan_details", "list_install_scripts", "inspect_lockfile_entry", "manifest", "list_findings",
    "get_finding", "list_hypotheses", "get_evidence", "list_proposals", "get_proposal",
})  # fmt: skip
DUPLICATE_AT = 2  # the third identical read-only call is answered with a notice
# Failures worth one more try: the tool did not give an answer, as opposed to giving a bad one.
TRANSIENT = (TimeoutError, ConnectionError)
MAX_RETRIES = 2
RETRY_BACKOFF_S = 0.5
PREVIEW_CHARS = 400
TEXT_CHARS = 3000


def _digest(messages: list) -> str:
    """Stable digest of the conversation sent to the model (the prompt itself is not stored)."""
    h = hashlib.sha256()
    for m in messages:
        h.update(f"{getattr(m, 'type', '?')}:{getattr(m, 'content', '')!s}".encode())
    return h.hexdigest()[:16]


def _thinking(message: AIMessage) -> str | None:
    """A provider's own reasoning text, when its integration exposes one. DeepSeek on DeepInfra
    does not (reasoning_tokens is 0), so this is usually None and the UI says so."""
    kw = message.additional_kwargs or {}
    for key in ("reasoning_content", "reasoning", "thinking"):
        if isinstance(kw.get(key), str) and kw[key].strip():
            return kw[key]
    if isinstance(message.content, list):
        parts = [
            b.get("thinking") or b.get("reasoning") or b.get("text") or ""
            for b in message.content
            if isinstance(b, dict) and b.get("type") in {"thinking", "reasoning"}
        ]
        return "\n".join(p for p in parts if p) or None
    return None


FAILURE_NOTICE_AT = 4


def _trailing_failures(messages: list) -> int:
    """How many tool results at the end of the conversation are errors (consecutively)."""
    count = 0
    for m in reversed(messages):
        if isinstance(m, ToolMessage):
            text = m.content if isinstance(m.content, str) else ""
            if m.status == "error" or text.startswith(("Error", '{"error"')):
                count += 1
                continue
            break
        if isinstance(m, AIMessage):
            continue  # the model turns between the tool results
        break
    return count


def _result_text(result: Any) -> str:
    """The readable text of a tool result. `task` returns a Command whose update carries the
    specialist's final message; other tools return a ToolMessage."""
    update = getattr(result, "update", None)
    if isinstance(update, dict) and update.get("messages"):
        result = update["messages"][-1]
    content = result.content if isinstance(result, ToolMessage | AIMessage) else str(result)
    return content if isinstance(content, str) else json.dumps(content, default=str)


def _text(message: AIMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    return json.dumps(content, default=str)


class AgentRuntime(AgentMiddleware):
    def __init__(
        self,
        session: Session,
        agent: str,
        allowed: frozenset[str],
        blocked: list[str],
        *,
        warns_on_budget: bool = False,
        step_limit: int = 12,
    ) -> None:
        super().__init__()
        self.S, self.agent, self.allowed, self.blocked = session, agent, allowed, blocked
        self.warns_on_budget = warns_on_budget
        self.step_limit = step_limit
        self._seen: dict[str, int] = {}  # identical read-only calls since the last state change

    @property
    def name(self) -> str:
        return f"AgentRuntime[{self.agent}]"

    def _emit(self, event: dict) -> None:
        if self.S.on_event is not None:
            self.S.on_event(event)

    # -- model calls -----------------------------------------------------------------------------
    @hook_config(can_jump_to=["end"])
    def before_model(self, state: Any, runtime: Any) -> dict | None:
        messages = state["messages"]
        # Model calls made so far in THIS invocation. Counted from the conversation itself, so
        # parallel invocations of the same specialist do not share a counter.
        used = sum(isinstance(m, AIMessage) for m in messages)
        if used >= self.step_limit:
            self.S.ledger.log(self.agent, "step_limit", None, {"limit": self.step_limit})
            note = (
                f"[{self.agent} stopped: it reached its limit of {self.step_limit} model calls "
                "for this task. Its work so far is in the tool results; it is incomplete.]"
            )
            return {"messages": [AIMessage(content=note)], "jump_to": "end"}
        self.S.budget.start_model_call()
        self.S.ledger.log(
            self.agent,
            "model_call",
            None,
            {
                "step": self.S.budget.steps,
                "messages": len(messages),
                "used": used,
                "prompt_digest": _digest(messages),
            },
        )
        notices = []
        failing = _trailing_failures(messages)
        if failing >= FAILURE_NOTICE_AT and failing % FAILURE_NOTICE_AT == 0:
            self.S.ledger.log(self.agent, "repeated_failures", None, {"count": failing})
            notices.append(
                f"REPEATED ERRORS NOTICE: your last {failing} tool calls all failed. Do not retry "
                "variations of the same call. Read the error messages, use a different tool or "
                "approach, or report this as a limit you could not get past."
            )
        if used == self.step_limit - 2:
            notices.append(
                f"STEP LIMIT NOTICE: you have {self.step_limit - used} model calls left for this "
                "task. Stop exploring now and write your final report from what you have."
            )
        if self.warns_on_budget and (notice := self.S.budget.take_warning()):
            self.S.ledger.log(self.agent, "budget_notice", None, {"text": notice})
            notices.append(notice)
        if notices:
            return {"messages": [HumanMessage(content=" ".join(notices))]}
        return None

    def after_model(self, state: Any, runtime: Any) -> dict | None:
        last = state["messages"][-1]
        if not isinstance(last, AIMessage):
            return None
        usage = last.usage_metadata or {}
        self.S.budget.add_usage(usage.get("input_tokens"), usage.get("output_tokens"))
        calls = [{"name": c["name"], "args": redact_obj(c.get("args"))} for c in last.tool_calls]
        self.S.ledger.log(
            self.agent,
            "model_response",
            None,
            {
                "text": redact(_text(last))[:TEXT_CHARS],
                "thinking": redact(t)[:TEXT_CHARS] if (t := _thinking(last)) else None,
                "tool_calls": calls,
                "tokens_in": usage.get("input_tokens"),
                "tokens_out": usage.get("output_tokens"),
            },
        )
        return None

    # -- tool calls ------------------------------------------------------------------------------
    def _call_with_retry(self, handler: Callable, request: Any, tool: str) -> Any:
        """Run a tool; retry a transient failure (timeout, dropped connection) a couple of times.
        Anything else, including a budget stop, is raised at once."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                return handler(request)
            except TRANSIENT as exc:
                if attempt == MAX_RETRIES:
                    raise
                log.warning("retrying %s:%s after %s", self.agent, tool, type(exc).__name__)
                self.S.ledger.log(self.agent, "tool_retry", tool, {"attempt": attempt + 1})
                time.sleep(RETRY_BACKOFF_S * (attempt + 1))
        raise AssertionError("unreachable")  # pragma: no cover

    def wrap_tool_call(self, request: Any, handler: Callable) -> Any:
        call = request.tool_call
        tool, args, call_id = call["name"], redact_obj(call.get("args") or {}), call["id"]
        if tool not in self.allowed:
            self.blocked.append(f"{self.agent}:{tool}")
            log.warning("blocked tool %s for agent %s (not in its roster)", tool, self.agent)
            self.S.ledger.log(self.agent, "blocked", tool, {"args": args})
            return ToolMessage(
                content=json.dumps({"error": f"tool '{tool}' is not available to {self.agent}"}),
                tool_call_id=call_id,
                status="error",
            )
        sig = f"{tool}:{json.dumps(call.get('args') or {}, sort_keys=True, default=str)}"
        if tool in READ_ONLY and self._seen.get(sig, 0) >= DUPLICATE_AT:
            n = self._seen[sig]
            log.warning("duplicate call skipped %s:%s (%d identical calls)", self.agent, tool, n)
            self.S.ledger.log(self.agent, "duplicate_call", tool, {"args": args, "count": n})
            return ToolMessage(
                content=json.dumps({"notice": (
                    f"You already made this exact {tool} call {n} times and the result has not "
                    "changed. Use the earlier result, or call something different."
                )}),
                tool_call_id=call_id,
            )
        self.S.budget.start_tool_call()
        kind = "delegate" if tool == "task" else "tool_call"
        if kind == "delegate":
            self.S.ledger.log(
                self.agent, "delegate_start", args.get("subagent_type"), {"args": args}
            )
        started = time.monotonic()
        try:
            result = self._call_with_retry(handler, request, tool)
        except BudgetExhausted:
            log.warning("budget exhausted at %s:%s", self.agent, tool)
            self.S.ledger.log(self.agent, "budget_exhausted", tool, {"args": args})
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            log.warning("tool error %s:%s %s", self.agent, tool, short(message, 160))
            event = {"args": args, "error": True, "message": redact(message)[:500]}
            self.S.ledger.log(self.agent, "tool_error", tool, event)
            self._emit({"agent": self.agent, "tool": tool, "args": args, "error": True})
            return ToolMessage(
                content=json.dumps({"error": message[:500]}), tool_call_id=call_id, status="error"
            )
        content = _result_text(result)
        if tool in READ_ONLY:
            self._seen[sig] = self._seen.get(sig, 0) + 1
        elif tool != "task":
            self._seen.clear()  # something may have changed, so earlier reads are no longer repeats
        event = {
            "args": args,
            "result_chars": len(content),
            "ms": int((time.monotonic() - started) * 1000),
            "error": content.startswith('{"error"'),
            "preview": redact(content)[:PREVIEW_CHARS],
        }
        if kind == "delegate":  # the specialist's final answer is the thing worth reading
            event["result_text"] = redact(content)[:6000]
        log.log(
            logging.WARNING if event["error"] else logging.INFO,
            "%s %s:%s %dms %d chars args=%s",
            kind, self.agent, tool, event["ms"], len(content), short(args),
        )
        self.S.ledger.log(self.agent, kind, tool, event)
        self._emit({"agent": self.agent, "tool": tool, "args": args, "error": event["error"]})
        return result
