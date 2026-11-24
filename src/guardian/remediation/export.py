"""Prepare an approved, validated fix for a human to push. Nothing is pushed from here.

``export_fix`` writes a patch (package.json and package-lock.json only) and a small metadata
file. ``scripts/push_fix.sh`` is the separate step a person runs with their own git credentials.
The server never sees a token and never talks to the user's repository.
"""

from __future__ import annotations

import hashlib
import json
import re

from guardian.remediation import proposals as props
from guardian.remediation import service, workspace
from guardian.remediation.proposals import ApprovalError
from guardian.sbom.build import load_target
from guardian.store import connect
from guardian.tools.runner import WORKSPACE, jail

GITHUB = re.compile(r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
PUSHABLE = {"verified", "partially_verified"}


def export_fix(db: str, run_id: str, proposal_id: str) -> dict:
    conn = connect(db)
    try:
        approval = props.require_approved(conn, run_id, proposal_id)  # human approval, SHA-bound
        proposal = props.get_proposal(conn, f"{run_id}:{proposal_id}")
        vals = props.validations(conn, run_id, proposal_id)
        base_target = service.run_target(conn, run_id)
    finally:
        conn.close()
    if not vals or vals[-1]["verdict"] not in PUSHABLE:
        got = vals[-1]["verdict"] if vals else "not validated"
        raise ApprovalError(f"only a verified or partially verified fix can be exported ({got})")
    target = load_target(base_target)
    repo = str(target.get("repo", ""))
    if not GITHUB.match(repo):
        raise ApprovalError("this target has no GitHub remote (for example the bundled demo)")
    work = jail(vals[-1]["branch"]["path"])
    workspace.git(work, "add", "package.json", "package-lock.json")
    files = ("package.json", "package-lock.json")
    patch = workspace.git(work, "diff", "--cached", "base", "--", *files)
    if not patch.strip():
        raise ApprovalError("the work copy has no change to export")

    out = jail(f"{run_id}/exports")
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{proposal.id}"
    (out / f"{stem}.patch").write_text(patch)
    meta = {
        "repo": repo,
        "base_commit": target.get("commit"),
        "branch": f"guardian/fix-{proposal.finding_id}".lower(),
        "title": f"guardian: {proposal.summary[:120]}",
        "proposal": proposal.id,
        "verdict": vals[-1]["verdict"],
        "approved_by": approval["approver"],
        "approved_at": approval["at"],
        "lockfile_origin": target.get("lockfile_origin", "repository"),
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
    }
    (out / f"{stem}.json").write_text(json.dumps(meta, indent=2) + "\n")
    rel = str((out / f"{stem}.json").relative_to(WORKSPACE))
    return {**meta, "metadata_file": rel, "command": f"scripts/push_fix.sh {rel}"}
