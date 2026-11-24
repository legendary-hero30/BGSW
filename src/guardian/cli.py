"""Guardian CLI.

  python -m guardian run --target nodegoat [--goal "..."] [--budget-steps 60 --budget-usd 5]
  python -m guardian trace  --agent-run <id>
  python -m guardian report --agent-run <id>
  python -m guardian sandboxes

A run needs a live model: DeepInfra (DeepSeek) by default, with DEEPINFRA_API_KEY and
GUARDIAN_ALLOW_EXTERNAL_MODELS=1 set (LLM_PROVIDERS.md). There is no offline model.
"""

from __future__ import annotations

import argparse
import json
import sys

from guardian.agents.budget import BudgetConfigError, BudgetLimits
from guardian.agents.ledger import Ledger
from guardian.agents.models import ModelConfig, ModelDisabledError, default_model
from guardian.agents.runner import DEFAULT_GOAL, run_goal
from guardian.envfile import load_env
from guardian.sandbox import backend_report
from guardian.store import DEFAULT_DB


def _add_run(sub) -> None:
    r = sub.add_parser("run", help="give the agents a goal and let them work")
    r.add_argument("--target", required=True, help="registered target name (targets/targets.json)")
    r.add_argument("--goal", default=DEFAULT_GOAL)
    r.add_argument("--out", help="run directory (default runs/agent-<target>-<timestamp>)")
    r.add_argument("--db", default=DEFAULT_DB)
    r.add_argument("--provider", default="deepinfra")
    r.add_argument("--model", help="model id (default per provider)")
    r.add_argument("--base-url")
    r.add_argument("--sandbox", default="auto", choices=("auto", "docker", "none"))
    r.add_argument("--budget-steps", type=int, help="max model calls across all agents (100)")
    r.add_argument("--budget-tool-calls", type=int, help="max tool calls (250)")
    r.add_argument("--budget-seconds", type=int, help="max wall-clock seconds (900)")
    r.add_argument("--budget-tokens", type=int, help="max total tokens (1200000)")
    r.add_argument("--budget-usd", type=float, help="max spend; needs GUARDIAN_PRICE_*_PER_M")
    r.add_argument("--quiet", action="store_true", help="do not print live tool calls")


def _cmd_run(a: argparse.Namespace) -> int:
    try:
        model = a.model or default_model(a.provider)
        limits = BudgetLimits.from_env(
            max_steps=a.budget_steps,
            max_tool_calls=a.budget_tool_calls,
            max_seconds=a.budget_seconds,
            max_tokens=a.budget_tokens,
            max_usd=a.budget_usd,
        )
    except (ValueError, BudgetConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    def live(event: dict) -> None:
        if not a.quiet:
            flag = " ERROR" if event.get("error") else ""
            print(f"  [{event['agent']}] {event['tool']}{flag}", flush=True)

    try:
        doc = run_goal(
            a.target,
            goal=a.goal,
            out_dir=a.out,
            db=a.db,
            limits=limits,
            sandbox=a.sandbox,
            cfg=ModelConfig(provider=a.provider, model=model, base_url=a.base_url),
            on_event=live,
        )
    except ModelDisabledError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    u = doc["usage"]
    print(
        f"Agent run {doc['agent_run_id']}  status {doc['status']}"
        + (f" ({doc['stop_reason']})" if doc["stop_reason"] else "")
    )
    print(f"Model     {doc['provider']}:{doc['model']}")
    print(
        f"Used      steps {u['steps']}, tool calls {u['tool_calls']}, {u['elapsed_s']}s, "
        f"tokens {u['tokens_in'] + u['tokens_out']}"
    )
    print(
        f"Plan      {len(doc['plan'])} items; hypotheses {len(doc['hypotheses'])}; "
        f"report accepted {doc['report_accepted']}"
    )
    print(f"Output    {doc['out_dir']}/agent-report.md, agent-run.json")
    return 0 if doc["status"] == "completed" else 1


def _cmd_trace(a: argparse.Namespace) -> int:
    ledger = Ledger(a.db, a.agent_run)
    try:
        info = ledger.run_info()
        print(f"{a.agent_run}: {info['status']} {info['provider']}:{info['model']}")
        print(f"goal: {info['goal']}")
        for e in ledger.events(tuple(a.kinds) if a.kinds else None):
            p = e["payload"]
            detail = (
                p.get("preview")
                or p.get("text")
                or p.get("message")
                or json.dumps(
                    {k: v for k, v in p.items() if k not in {"prompt_digest"}}, default=str
                )
            )
            print(
                f"{e['seq']:>4} {e['ts'][11:23]} {e['agent']:<12} {e['kind']:<15} "
                f"{e['name'] or '':<22} {str(detail)[:110]}"
            )
    finally:
        ledger.close()
    return 0


def _cmd_report(a: argparse.Namespace) -> int:
    ledger = Ledger(a.db, a.agent_run)
    try:
        info = ledger.run_info()
    finally:
        ledger.close()
    if not info["report_md"]:
        print(
            f"agent run {a.agent_run} has no accepted report (status {info['status']})",
            file=sys.stderr,
        )
        return 1
    print(info["report_md"])
    return 0


def _cmd_approvals(a: argparse.Namespace) -> int:
    from guardian.remediation import proposals as props
    from guardian.remediation import service
    from guardian.store import connect

    conn = connect(a.db)
    try:
        if a.action == "list":
            rows = props.list_proposals(conn, a.run)
            for p in rows:
                st = props.status(conn, a.run, p.id).value
                print(f"{p.id}  {st:<9} {p.action.value:<18} {p.finding_id}  {p.summary}")
            if not rows:
                print("no proposals for this run")
            return 0
        if a.action == "show":
            print(json.dumps(service.view(conn, a.run, a.proposal, full=True), indent=2))
            return 0
        if a.action in {"approve", "reject"}:
            if not a.approver:
                print("--approver NAME is required: approvals are logged with who and when",
                      file=sys.stderr)  # fmt: skip
                return 2
            rec = props.decide(conn, a.run, a.proposal, a.action + "d", a.approver, a.note or "")
            print(json.dumps(rec, indent=2))
            return 0
    except (props.ApprovalError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    try:  # validate
        report = service.validate_for_run(a.db, a.run, a.proposal, on_step=print)
    except (props.ApprovalError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps({k: report.get(k) for k in ("verdict", "reasons", "steps", "risk")}, indent=2))
    return 0 if report["verdict"] in {"verified", "partially_verified"} else 1


def main(argv: list[str] | None = None) -> int:
    load_env()  # settings from the git-ignored .env; real environment variables win
    p = argparse.ArgumentParser(prog="guardian")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add_run(sub)
    for name, help_ in (
        ("trace", "show the audit trail of an agent run"),
        ("report", "print the accepted report of an agent run"),
    ):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--agent-run", required=True)
        s.add_argument("--db", default=DEFAULT_DB)
        if name == "trace":
            s.add_argument("--kinds", nargs="*", help="e.g. plan tool_call delegate hypothesis")
    ap = sub.add_parser("approvals", help="list, approve, reject or validate fix proposals")
    ap.add_argument("action", choices=["list", "show", "approve", "reject", "validate"])
    ap.add_argument("--run", required=True, help="run id, e.g. runs/OWASP__NodeGoat-...")
    ap.add_argument("proposal", nargs="?", help="proposal id, e.g. R-001")
    ap.add_argument("--approver", help="your name; logged with the decision and time")
    ap.add_argument("--note")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub.add_parser("sandboxes", help="show which isolation backends are usable here")
    a = p.parse_args(argv)
    if a.cmd == "run":
        return _cmd_run(a)
    if a.cmd == "trace":
        return _cmd_trace(a)
    if a.cmd == "approvals":
        if a.action != "list" and not a.proposal:
            p.error("a proposal id is required")
        return _cmd_approvals(a)
    if a.cmd == "report":
        return _cmd_report(a)
    print(json.dumps(backend_report(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
