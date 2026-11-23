"""CLI:
  uv run --locked python -m guardian.agents analyze --run runs/demo [--limit 10]
  uv run --locked python -m guardian.agents run --target nodegoat --out runs/demo

Every run uses a live model. DeepInfra is the configured provider and has a default tool-calling
model, so ``--provider deepinfra`` is usually enough. External calls require
``GUARDIAN_ALLOW_EXTERNAL_MODELS=1`` and ``DEEPINFRA_API_KEY`` (see LLM_PROVIDERS.md).
"""

from __future__ import annotations

import argparse
import json
import sys

from guardian.agents.models import ModelConfig, ModelDisabledError, default_model
from guardian.agents.orchestrator import run_agents
from guardian.agents.report import export
from guardian.agents.tools import AgentContext
from guardian.store import DEFAULT_DB
from guardian.tools.runner import jail, workspace_relative


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardian.agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("analyze", "run"):
        s = sub.add_parser(name)
        s.add_argument("--db", default=DEFAULT_DB)
        s.add_argument("--provider", default="deepinfra")
        s.add_argument("--model", help="model id (defaults per provider, e.g. DeepInfra DeepSeek)")
        s.add_argument("--base-url")
        s.add_argument("--limit", type=int, default=10)
        if name == "analyze":
            s.add_argument("--run", required=True, help="stored run id, e.g. runs/demo")
        else:
            s.add_argument("--target", required=True)
            s.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        model = a.model or default_model(a.provider)
    except ValueError as exc:
        p.error(str(exc))
    cfg = ModelConfig(provider=a.provider, model=model, base_url=a.base_url)

    if a.cmd == "analyze":
        run_id = workspace_relative(jail(a.run))
        summary = json.loads((jail(run_id) / "baseline.json").read_text())
        ctx = AgentContext(
            target=summary["target"]["name"],
            out_dir=run_id,
            db=a.db,
            provider=cfg.provider,
            model=cfg.model,
            run_id=run_id,
            max_findings=a.limit,
        )
        mode = "analyze"
    else:
        from guardian.sbom.build import build as build_sbom
        from guardian.scan.baseline import baseline

        out = workspace_relative(jail(a.out))
        jail(out).mkdir(parents=True, exist_ok=True)
        ctx = AgentContext(
            target=a.target,
            out_dir=out,
            db=a.db,
            provider=cfg.provider,
            model=cfg.model,
            max_findings=a.limit,
            discover=build_sbom,
            detect=lambda t, o, d: baseline(t, o, db=d),
        )
        mode = "full"
    try:
        outcome = run_agents(ctx, cfg, mode)
    except ModelDisabledError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if ctx.run_id is None:
        print("no stored run was produced", file=sys.stderr)
        return 1
    doc = export(ctx, cfg, outcome)
    print(f"Agents   {ctx.provider}:{ctx.model} ({doc['generator']}) on {ctx.run_id}")
    print(
        f"Accepted {len(doc['accepted'])}  rejected attempts {len(doc['rejected'])}  "
        f"blocked tool calls {len(outcome['blocked_tool_calls'])}  tool calls "
        f"{outcome['tool_calls']}"
    )
    print(f"Final    {outcome['final'][:200]}")
    print(f"Output   {ctx.out_dir}/explanations.md")
    return 0 if doc["accepted"] and not outcome["blocked_tool_calls"] else 1


if __name__ == "__main__":
    sys.exit(main())
