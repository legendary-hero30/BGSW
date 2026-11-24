"""Builds the agent graph: a supervisor and specialists on LangChain Deep Agents.

There is no workflow here. The supervisor is given a goal and a roster; it plans, delegates with
the ``task`` tool, revises, and decides when to stop. Each specialist is defined by a prompt
(``prompts/``), a tool set (``toolkit.ROSTER_TOOLS``) and the shared Session.
"""

from __future__ import annotations

import hashlib

from deepagents import (
    FilesystemMiddleware,
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    SubAgent,
    create_deep_agent,
    register_harness_profile,
)
from langchain_core.language_models.chat_models import BaseChatModel

from guardian.agents.models import provider_key
from guardian.agents.runtime import AgentRuntime
from guardian.agents.session import Session
from guardian.agents.toolkit import ROSTER_TOOLS, build_tools
from guardian.tools.runner import WORKSPACE

PROMPTS_DIR = WORKSPACE / "prompts"
READ_FILE_NOTE = {
    "read_file": (
        "Reads Deep Agents' internal scratch space ONLY. It cannot read the repository or the "
        "run directory: every path you try will fail. Use read_repo_file to read repository files."
    )
}
BUILTIN_FS = ("read_file",)  # cannot be removed; reads only the in-state virtual filesystem
SPECIALISTS = {
    "inventory": "What the application is made of: files, SBOM, dependency graph, paths.",
    "vulnerability": "Runs offline dependency vulnerability scanners and exploitability lookups.",
    "forensics": "Non-CVE supply-chain risk: typosquats, install scripts, odd sources, lockfile.",
    "container_ci": "Dockerfile, base image and CI/CD workflow risk.",
    "remediation": "Proposes safe fixes (upgrade, pin, escalate) for findings; never applies them.",
    "validation": "Validates a human-approved proposal on an isolated branch: rescan and diffs.",
    "risk": "Builds scored findings, explains them through a gate, records hypotheses.",
    "verifier": "Independently checks hypotheses and citations; rejects unsupported claims.",
}


# Model calls one invocation of a role may make (enforced in AgentRuntime). Sized from live runs:
# enough for a thorough pass, small enough that one agent cannot spend the run.
STEP_LIMITS = {
    "supervisor": 40,
    "inventory": 10,
    "vulnerability": 8,
    "forensics": 14,
    "container_ci": 8,
    "risk": 16,
    "remediation": 10,
    "validation": 6,
    "verifier": 10,
}


class UnsafeAgentError(RuntimeError):
    pass


def load_prompts() -> dict[str, str]:
    """Role prompt = common rules + role text. Returned by role name."""
    common = (PROMPTS_DIR / "common.md").read_text()
    names = ["supervisor", *SPECIALISTS]
    return {n: f"{(PROMPTS_DIR / f'{n}.md').read_text()}\n\n{common}" for n in names}


def prompt_versions() -> dict[str, str]:
    """SHA-256 prefix of each prompt file, recorded with every run (what the agents were told)."""
    return {
        p.stem: hashlib.sha256(p.read_bytes()).hexdigest()[:16]
        for p in sorted(PROMPTS_DIR.glob("*.md"))
    }


def build_supervisor(model: BaseChatModel, S: Session, blocked: list[str]):  # noqa: N803
    key = provider_key(model)
    if key:  # we supply our own roster; drop the auto-added general-purpose subagent
        register_harness_profile(
            key,
            HarnessProfile(general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False)),
        )
    prompts = load_prompts()
    tools = build_tools(S)

    def middleware(agent: str, allowed: frozenset[str], supervisor: bool = False) -> list:
        return [
            FilesystemMiddleware(tools=list(BUILTIN_FS), custom_tool_descriptions=READ_FILE_NOTE),
            AgentRuntime(
                S,
                agent,
                allowed | set(BUILTIN_FS),
                blocked,
                warns_on_budget=supervisor,
                step_limit=STEP_LIMITS[agent],
            ),
        ]

    subagents: list[SubAgent] = []
    for name, description in SPECIALISTS.items():
        names = ROSTER_TOOLS[name]
        subagents.append(
            {
                "name": name,
                "description": description,
                "system_prompt": prompts[name],
                "tools": [tools[t] for t in names],
                "model": model,
                "middleware": middleware(name, frozenset(names)),
            }
        )
    main_names = ROSTER_TOOLS["supervisor"]
    agent = create_deep_agent(
        model=model,
        tools=[tools[t] for t in main_names],
        system_prompt=prompts["supervisor"],
        subagents=subagents,
        middleware=middleware("supervisor", frozenset({*main_names, "task"}), supervisor=True),
        name="guardian-supervisor",
    )
    exposed = set(agent.nodes["tools"].bound.tools_by_name)
    extra = exposed - {*main_names, "task", *BUILTIN_FS}
    if extra:
        raise UnsafeAgentError(f"the supervisor exposes tools beyond its roster: {sorted(extra)}")
    return agent
