"""One agent run's shared working state: goal, budget, ledger, pipeline and sandbox.

Every agent and tool closes over the same Session. It is the "shared state" of AGENTS.md
section 1.6: stage results live in the run directory, findings and the audit trail live in the
evidence store, and nothing is passed along a fixed chain.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from guardian.agents.budget import BudgetTracker
from guardian.agents.ledger import Ledger
from guardian.sandbox import Sandbox
from guardian.scan.pipeline import Pipeline
from guardian.schemas.finding import Finding, FindingSet
from guardian.schemas.graph import DependencyGraph
from guardian.store import connect, load_findings


class AgentToolError(Exception):
    """A tool could not do what was asked. The message is for the agent to read and adapt to."""


@dataclass
class Session:
    goal: str
    target: str
    out_dir: str
    db: str
    provider: str
    model: str
    ledger: Ledger
    budget: BudgetTracker
    pipeline: Pipeline
    sandbox: Sandbox | None = None
    sandbox_reason: str = "sandbox not configured"
    cache: dict[str, object] = field(default_factory=dict)
    on_event: Callable[[dict], None] | None = None  # live progress (UI jobs)
    findings_built: bool = False
    builds: int = 0
    fingerprint: str | None = None
    injection_flags: list[dict] = field(default_factory=list)
    report_markdown: str | None = None
    _fs: FindingSet | None = None
    _graph: DependencyGraph | None = None

    @property
    def run_id(self) -> str:
        return self.pipeline.run_id

    def invalidate(self) -> None:
        self._fs = None
        self._graph = None

    def finding_set(self) -> FindingSet:
        if not self.findings_built:
            raise AgentToolError("no findings yet: build_findings must run after at least one scan")
        if self._fs is None:
            conn = connect(self.db)
            try:
                self._fs = load_findings(conn, self.run_id)
            finally:
                conn.close()
        return self._fs

    def findings(self) -> dict[str, Finding]:
        return {f.id: f for f in self.finding_set().findings}

    def evidence(self) -> dict:
        return {r.id: r for r in self.finding_set().evidence}

    def graph(self) -> DependencyGraph:
        if self._graph is None:
            self._graph = self.pipeline.graph()
        return self._graph
