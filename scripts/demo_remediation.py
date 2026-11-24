"""End-to-end Day 2 demo: Prioritized Risk -> Recommended Fix -> Human Approval -> Build & Test
-> Rescan -> Verified Remediation, on the small sample app in demo/vulnerable-app.

    python3 scripts/demo_remediation.py --allow-external-models --allow-registry \\
        [--approve-as "Your Name"]

Without --approve-as the script stops at the approval gate and asks you, per proposal. Passing
--approve-as is you approving every applicable proposal under that name (logged with the time).
Agents never approve. Needs the DeepInfra key (DEEPINFRA_API_KEY or the key file),
npm registry access for the lockfile step, and bubblewrap for the build/test sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guardian import cli  # noqa: E402
from guardian.envfile import load_env  # noqa: E402
from guardian.remediation import proposals as props  # noqa: E402
from guardian.remediation import service  # noqa: E402
from guardian.store import DEFAULT_DB, connect  # noqa: E402
from guardian.targets import _register  # noqa: E402

NAME = "guardian-demo-app"
SRC = ROOT / "demo" / "vulnerable-app"
DEST = ROOT / "targets" / "dynamic" / NAME
KEYFILE = Path.home() / ".config" / "guardian" / "deepinfra.key"

GOAL_1 = (
    "Assess this application's supply-chain risk. Then, for the highest-risk findings that have "
    "a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at "
    "the human approval gate and report the pending proposals with their expected risk "
    "reduction, compatibility impact and rollback."
)
GOAL_2 = (
    "A human has reviewed the remediation proposals of the existing run. Using the validation "
    "specialist, validate every proposal that is approved (not the others), and report each "
    "verdict exactly: what was resolved, any new findings, build and test results, and what "
    "could not be verified. Do not rebuild findings."
)


def prepare() -> None:
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(SRC, DEST, ignore=shutil.ignore_patterns("node_modules"))
    digest = hashlib.sha256((DEST / "package-lock.json").read_bytes()).hexdigest()[:40]
    _register({
        "name": NAME, "repo": "local demo (demo/vulnerable-app)", "commit": digest,
        "commit_date": None, "license": "MIT", "ecosystem": "npm",
        "lockfile": "package-lock.json", "path": str(DEST.relative_to(ROOT)),
        "read_only": False, "dynamic": True, "selected": "Guardian remediation demo app",
    })  # fmt: skip


def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument(
        "--allow-external-models", action="store_true", help="send run metadata to DeepInfra"
    )
    ap.add_argument(
        "--allow-registry",
        action="store_true",
        help="allow npm registry access for the lockfile/install steps",
    )
    ap.add_argument("--approve-as", help="approve all applicable proposals as this named human")
    ap.add_argument("--db", default=DEFAULT_DB)
    a = ap.parse_args()
    if not (a.allow_external_models and a.allow_registry):
        print(
            "pass --allow-external-models and --allow-registry (explicit opt-ins)", file=sys.stderr
        )
        return 2
    load_env()
    os.environ["GUARDIAN_ALLOW_EXTERNAL_MODELS"] = "1"
    os.environ["GUARDIAN_ALLOW_REGISTRY_ACCESS"] = "1"
    if not os.environ.get("DEEPINFRA_API_KEY") and KEYFILE.is_file():
        os.environ["DEEPINFRA_API_KEY"] = KEYFILE.read_text().strip()
    if not os.environ.get("DEEPINFRA_API_KEY"):
        print(
            "no DeepInfra key (DEEPINFRA_API_KEY or ~/.config/guardian/deepinfra.key)",
            file=sys.stderr,
        )
        return 2

    out = f"runs/demo-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    banner("1/5  Prepare the sample app as a target")
    prepare()
    print(f"registered {NAME} at {DEST.relative_to(ROOT)}")

    banner("2/5  Agents assess the app and propose fixes (nothing is applied)")
    rc = cli.main(["run", "--target", NAME, "--goal", GOAL_1, "--out", out, "--db", a.db,
                   "--budget-steps", "100", "--budget-seconds", "900"])  # fmt: skip
    conn = connect(a.db)
    rows = props.list_proposals(conn, out)
    if rc not in (0, 1) or not rows:
        print(f"agents finished with code {rc} and {len(rows)} proposals", file=sys.stderr)
        return 1

    banner("3/5  Human approval gate")
    for p in rows:
        v = service.view(conn, out, p.id)
        print(f"\n{p.id} [{v['status']}] {p.summary}\n   compat {p.compatibility.level}; "
              f"resolves {list(p.expected_risk_reduction.findings_resolved)}; "
              f"rollback: {p.rollback[0]}")  # fmt: skip
        if not p.applicable:
            print("   (no file change: recorded for a human reviewer, not approvable)")
            continue
        who = a.approve_as
        if not who:
            if input("   approve? [y/N] ").strip().lower() != "y":
                props.decide(
                    conn, out, p.id, "rejected", input("   your name: ").strip() or "unknown"
                )
                continue
            who = input("   your name (logged): ").strip()
        print(
            f"   approved by {who}:", props.decide(conn, out, p.id, "approved", who, "demo")["at"]
        )

    banner("4/5  Validation agent: apply on a branch, build, test, rescan, diff")
    rc = cli.main(["run", "--target", NAME, "--goal", GOAL_2, "--out", out, "--db", a.db,
                   "--budget-steps", "40", "--budget-seconds", "900"])  # fmt: skip

    banner("5/5  Result (from the evidence store, not the model)")
    for p in rows:
        for v in props.validations(conn, out, p.id):
            st = v.get("steps", {})
            print(f"{p.id}: {v['verdict'].upper()}  build={st.get('build', {}).get('status')} "
                  f"tests={st.get('tests', {}).get('status')}")  # fmt: skip
            for r in v.get("reasons", []):
                print(f"   - {r}")
            risk = v.get("risk")
            if risk:
                print(f"   risk {risk['before']['levels']} -> {risk['after']['levels']}")
    print(f"\nRun: {out}\nUI:  python -m guardian.api  ->  Remediation tab\n"
          f"Audit trail: python -m guardian trace --agent-run <id>")  # fmt: skip
    conn.close()
    print(json.dumps({"run": out}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
