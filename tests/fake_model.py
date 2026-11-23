"""Test-only chat model that drives the real tool protocol without network access.

This is NOT used by the product. Production builds a live model through
``guardian.agents.models.build_model``. Tests inject this fixture into ``run_agents`` so the
orchestrator, tools and deterministic gate can be exercised offline.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from guardian.agents.gate import REACH_WORDS
from guardian.schemas.risk import Reachability

TYPE_WORDS = {
    "vulnerable_direct": "A known vulnerability in a direct dependency",
    "vulnerable_transitive": "A known vulnerability in a transitive dependency",
    "malicious_package": "package advisory",
    "vulnerable_image_package": "A known vulnerability in a container image package",
}
SCANNERS = {"grype", "trivy", "osv-scanner"}


def _tool_results(messages: list[BaseMessage], name: str) -> list[str]:
    calls = {c["id"]: c["name"] for m in messages if isinstance(m, AIMessage)
             for c in m.tool_calls}  # fmt: skip
    return [m.content for m in messages if isinstance(m, ToolMessage)
            and calls.get(m.tool_call_id) == name and isinstance(m.content, str)]  # fmt: skip


def _call(name: str, args: dict, n: int) -> dict:
    return {"name": name, "args": args, "id": f"call_{name}_{n}", "type": "tool_call"}


class FakeChatModel(BaseChatModel):
    """Deterministic policy for tests. Chooses the next step from the bound tools and history."""

    model_name: str = "test-fixture"
    mode: str = "faithful"  # or "hallucinate": invents an advisory and a citation (gate test)
    bound: tuple[str, ...] = ()

    @property
    def _llm_type(self) -> str:
        return "guardian-test-fixture"

    def _get_ls_params(self, **kwargs: Any) -> dict:
        return {"ls_provider": "guardian-test", "ls_model_name": self.model_name,
                "ls_model_type": "chat"}  # fmt: skip

    def bind_tools(self, tools: Any, **kwargs: Any) -> FakeChatModel:
        names = []
        for t in tools:
            names.append(getattr(t, "name", None) or (t.get("name") if isinstance(t, dict)
                                                       else None) or "")  # fmt: skip
        return self.model_copy(update={"bound": tuple(names)})

    def _generate(self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None,
                  **kwargs: Any) -> ChatResult:  # fmt: skip
        return ChatResult(generations=[ChatGeneration(message=self._next(messages))])

    def _next(self, messages: list[BaseMessage]) -> AIMessage:
        n = sum(isinstance(m, AIMessage) for m in messages)
        tools = set(self.bound)
        if "task" in tools:
            return self._orchestrate(messages, n)
        if "submit_explanations" in tools:
            return self._analyze(messages, n)
        for name in ("run_discovery", "run_detection"):
            if name in tools:
                done = _tool_results(messages, name)
                if not done:
                    return AIMessage(content="", tool_calls=[_call(name, {}, n)])
                return AIMessage(content=f"{name} finished: {done[-1][:1500]}")
        return AIMessage(content="No applicable tools.")

    def _orchestrate(self, messages: list[BaseMessage], n: int) -> AIMessage:
        first = next((m.content for m in messages if isinstance(m, HumanMessage)), "")
        plan = ["analysis"] if "MODE=analyze" in str(first) else ["discovery", "detection",
                                                                    "analysis"]  # fmt: skip
        done = len(_tool_results(messages, "task"))
        if done < len(plan):
            step = plan[done]
            return AIMessage(content="", tool_calls=[_call("task", {
                "subagent_type": step,
                "description": f"Run the {step} stage for the configured target and report.",
            }, n)])  # fmt: skip
        return AIMessage(content=f"Run complete: {', '.join(plan)} finished.")

    def _analyze(self, messages: list[BaseMessage], n: int) -> AIMessage:
        listed = _tool_results(messages, "list_findings")
        if not listed:
            return AIMessage(content="", tool_calls=[_call("list_findings", {"limit": 10}, n)])
        ids = [x["id"] for x in json.loads(listed[-1])]
        details = [
            json.loads(x) for x in _tool_results(messages, "get_finding") if x.startswith("{")
        ]
        missing = [i for i in ids if i not in {d["id"] for d in details}]
        if missing:
            return AIMessage(content="", tool_calls=[
                _call("get_finding", {"finding_id": i}, n * 100 + k) for k, i in enumerate(missing)
            ])  # fmt: skip
        submitted = _tool_results(messages, "submit_explanations")
        if not submitted:
            return AIMessage(content="", tool_calls=[_call("submit_explanations", {
                "explanations": [self._explain(d) for d in details]}, n)])  # fmt: skip
        return AIMessage(content=f"Analysis complete. Gate result: {submitted[-1]}")

    def _explain(self, d: dict) -> dict:
        c, fx, risk = d["component"], d["factors"], d["risk"] or {}
        label = f"{c['name']}@{c['version']}" if c.get("version") else c["name"]
        what = TYPE_WORDS.get(d["type"], f"A {d['type'].replace('_', ' ')} finding")
        ids = ", ".join(d["advisory_ids"][:2])
        why = (f"{what} affects {label}" + (f" ({ids})" if ids else "")
               + f"; risk score {risk.get('score')} ({risk.get('level')}), "
                 f"severity {d['severity']}.")  # fmt: skip
        reach = Reachability(fx["reachability"])
        reach_text = {
            Reachability.IMPORTED: "The app's server code imported this exact installed copy",
            Reachability.PRESENT_ONLY: "The package is present in the runtime tree but no "
                                       "direct import by the app was found",
            Reachability.DEV_ONLY_UNUSED: "The package is dev-only, so production does not load it",
            Reachability.UNKNOWN: "Reachability is unknown for this kind of finding",
            Reachability.CALLED: "The vulnerable code is called by the app",
        }[reach]  # fmt: skip
        if REACH_WORDS[reach] not in reach_text.lower():
            raise ValueError(f"template for {reach} must contain {REACH_WORDS[reach]!r}")
        tools = {e["tool"] for e in d["evidence"]} & SCANNERS
        confidence = "high" if len(tools) >= 2 else "medium"
        cited = [e["id"] for e in d["evidence"]][:4]
        out = {
            "finding_id": d["id"], "why_it_matters": why,
            "reachability": f"{reach_text}; exposure is {fx['exposure'].replace('_', ' ')}.",
            "confidence": confidence,
            "confidence_reason": (f"{len(tools)} independent scanners reported it" if tools
                                  else "deterministic rule evidence"),
            "cited_evidence": cited,
        }  # fmt: skip
        if self.mode == "hallucinate":
            out["why_it_matters"] += " It is also tracked as CVE-2099-0001."
            out["cited_evidence"] = [*cited, "E-9999"]
        return out
