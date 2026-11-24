"""Run budgets (AGENTS.md section 2): steps, tool calls, wall-clock time, tokens and LLM spend.

A *step* is one model call by any agent. On exhaustion a ``BudgetExhausted`` is raised from the
agent middleware; Deep Agents lets tool exceptions propagate, so it unwinds through nested
subagents to the runner, which stops and reports what exists and what could not be finished.

Spend is only enforced when prices are configured: DeepInfra prices are not assumed.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import asdict, dataclass

PRICE_IN_ENV = "GUARDIAN_PRICE_IN_PER_M"
PRICE_OUT_ENV = "GUARDIAN_PRICE_OUT_PER_M"
WARN_FRACTION = 0.8


# Raised to stop a run when a limit is reached (steps, tools, time, tokens).
class BudgetExhausted(RuntimeError):  # noqa: N818 - control-flow signal, like StopIteration
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BudgetConfigError(ValueError):
    pass


@dataclass(frozen=True)
# The per-run limits. Defaults can be overridden from the environment.
class BudgetLimits:
    max_steps: int = 100
    max_tool_calls: int = 250
    max_seconds: int = 900
    max_tokens: int = 1_200_000
    max_usd: float | None = None
    price_in_per_m: float | None = None  # USD per million input tokens
    price_out_per_m: float | None = None

    def validate(self) -> None:
        for name in ("max_steps", "max_tool_calls", "max_seconds", "max_tokens"):
            if getattr(self, name) < 1:
                raise BudgetConfigError(f"{name} must be at least 1")
        if self.max_usd is not None:
            if self.max_usd <= 0:
                raise BudgetConfigError("max_usd must be positive")
            if self.price_in_per_m is None or self.price_out_per_m is None:
                raise BudgetConfigError(
                    f"a USD budget needs model prices: set {PRICE_IN_ENV} and {PRICE_OUT_ENV} "
                    "(USD per million tokens). Prices are not assumed."
                )

    @classmethod
    def from_env(cls, **overrides) -> BudgetLimits:
        def price(name: str) -> float | None:
            raw = os.environ.get(name)
            return float(raw) if raw else None

        values = {"price_in_per_m": price(PRICE_IN_ENV), "price_out_per_m": price(PRICE_OUT_ENV)}
        values.update({k: v for k, v in overrides.items() if v is not None})
        limits = cls(**values)
        limits.validate()
        return limits


# Counts model calls, tool calls, time and tokens against the limits.
class BudgetTracker:
    """Thread-safe usage counters shared by every agent in a run."""

    def __init__(self, limits: BudgetLimits) -> None:
        limits.validate()
        self.limits = limits
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self.steps = 0
        self.tool_calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.unknown_usage_calls = 0  # model calls whose response carried no token usage
        self.exhausted: str | None = None
        self._warned = False

    # -- accounting -------------------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    @property
    def usd(self) -> float | None:
        if self.limits.price_in_per_m is None or self.limits.price_out_per_m is None:
            return None
        return (
            self.tokens_in * self.limits.price_in_per_m
            + self.tokens_out * self.limits.price_out_per_m
        ) / 1_000_000

    # Raise BudgetExhausted if any limit has been reached.
    def check(self) -> None:
        """Raise BudgetExhausted if any limit is spent. Called before every model/tool call."""
        with self._lock:
            reason = self._exhausted_reason()
            if reason:
                self.exhausted = self.exhausted or reason
                raise BudgetExhausted(self.exhausted)

    def _exhausted_reason(self) -> str | None:
        lim = self.limits
        if self.steps >= lim.max_steps:
            return f"step budget spent ({self.steps}/{lim.max_steps} model calls)"
        if self.tool_calls >= lim.max_tool_calls:
            return f"tool-call budget spent ({self.tool_calls}/{lim.max_tool_calls})"
        if self.elapsed() >= lim.max_seconds:
            return f"time budget spent ({self.elapsed():.0f}s/{lim.max_seconds}s)"
        if self.tokens >= lim.max_tokens:
            return f"token budget spent ({self.tokens}/{lim.max_tokens})"
        usd = self.usd
        if lim.max_usd is not None and usd is not None and usd >= lim.max_usd:
            return f"spend budget spent (${usd:.4f}/${lim.max_usd:.2f})"
        return None

    def start_model_call(self) -> None:
        self.check()
        with self._lock:
            self.steps += 1

    def start_tool_call(self) -> None:
        self.check()
        with self._lock:
            self.tool_calls += 1

    def add_usage(self, tokens_in: int | None, tokens_out: int | None) -> None:
        with self._lock:
            if tokens_in is None and tokens_out is None:
                self.unknown_usage_calls += 1
                return
            self.tokens_in += int(tokens_in or 0)
            self.tokens_out += int(tokens_out or 0)

    # -- reporting ----------------------------------------------------------------------------
    def fraction_used(self) -> float:
        lim = self.limits
        fractions = [
            self.steps / lim.max_steps,
            self.tool_calls / lim.max_tool_calls,
            self.elapsed() / lim.max_seconds,
            self.tokens / lim.max_tokens,
        ]
        usd = self.usd
        if lim.max_usd is not None and usd is not None:
            fractions.append(usd / lim.max_usd)
        return max(fractions)

    # One-time warning when most of a budget is used, so agents can wrap up.
    def take_warning(self) -> str | None:
        """One-time notice once 80% of any budget is spent, so the agent can wrap up."""
        with self._lock:
            if self._warned or self.fraction_used() < WARN_FRACTION:
                return None
            self._warned = True
        return (
            f"BUDGET NOTICE: {self.fraction_used():.0%} of a run budget is used "
            f"({self.describe()}). Finish the most valuable remaining work, then submit the "
            "final report. Do not start new broad investigations."
        )

    def describe(self) -> str:
        lim = self.limits
        parts = [
            f"steps {self.steps}/{lim.max_steps}",
            f"tool calls {self.tool_calls}/{lim.max_tool_calls}",
            f"time {self.elapsed():.0f}s/{lim.max_seconds}s",
            f"tokens {self.tokens}/{lim.max_tokens}",
        ]
        if lim.max_usd is not None and self.usd is not None:
            parts.append(f"spend ${self.usd:.4f}/${lim.max_usd:.2f}")
        return ", ".join(parts)

    # Current usage and limits as plain data for the ledger and UI.
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "steps": self.steps,
                "tool_calls": self.tool_calls,
                "elapsed_s": round(self.elapsed(), 1),
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
                "unknown_usage_calls": self.unknown_usage_calls,
                "usd": None if self.usd is None else round(self.usd, 6),
                "usd_enforced": self.limits.max_usd is not None,
                "exhausted": self.exhausted,
                "limits": asdict(self.limits),
            }
