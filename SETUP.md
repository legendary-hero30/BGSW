# Setup

Everything here was run on WSL2 (Linux 6.18), Python 3.12.16 via `uv`. Anything not verified in
that environment is marked **unverified**.

## Requirements

- `uv` 0.13.9. Python 3.12 (uv installs cpython 3.12.16). The system `python3` is not used.
- Node 26 and npm 11 (only to build the UI, and for the Day 2 lockfile step).
- Scanner binaries and offline databases (sections below). Docker is optional (sandbox).

## Reproduce the environment

```bash
cd /home/suthekshan/bosch
uv sync --locked --extra llm-openai   # the OpenAI-compatible client is the only model extra
uv run --locked ruff check . && uv run --locked ruff format --check .
uv run --locked --extra llm-openai pytest -q     # ~3 min (integration tests run the scanners)
uv lock --check                                  # 73 packages; cooldown cutoff 2026-11-16
```

Dependencies are pinned by `uv.lock`; `exclude-newer` in `pyproject.toml` keeps every
resolution at least 7 days old. The UI has its own pins and settings in `ui/.npmrc`
(`ignore-scripts`, `save-exact`, `before=2026-11-16`).

## Configuration and secrets

Step-by-step browser demo: [DEMO.md](DEMO.md).

The Guardian has no offline or mock model. A run needs a real model:

| Variable | Meaning |
|---|---|
| `DEEPINFRA_API_KEY` | DeepInfra key. Put it in the git-ignored `.env` (copy `.env.example`, `chmod 600 .env`); the CLI, the API server and the demo script load it. A shell export overrides it. Never commit it. |
| `GUARDIAN_ALLOW_EXTERNAL_MODELS=1` | Required. Without it a run refuses before doing anything. |
| `GUARDIAN_PRICE_IN_PER_M`, `GUARDIAN_PRICE_OUT_PER_M` | USD per million tokens; only needed for `--budget-usd`. |
| `GUARDIAN_SANDBOX_IMAGE` | Digest-pinned image (`name@sha256:...`) enabling `sandbox_exec`. |
| `GUARDIAN_ALLOW_REGISTRY_ACCESS=1` | Day 2 only: lets validation regenerate `package-lock.json` (one networked step). |
| `GUARDIAN_LIVE_TESTS=1` | Opt in to the paid live-model test. |

Provider details: `LLM_PROVIDERS.md` (default `deepinfra`, model `deepseek-ai/DeepSeek-V4.1-Flash-1017`).
Secrets are redacted before anything is stored or sent to a model.

## Scanner binaries (D1.S2)

```bash
python3 -I scripts/install_tools.py        # downloads ~240 MB into tools/downloads and verifies SHA-256
tools/bin/syft --version                   # syft 1.57.2
```

The pins and hashes are in `tools/manifest.json`. `tools/bin/` and `tools/downloads/` are
git-ignored and reproduced from the manifest.

## Sample target (D1.S2)

```bash
git -c core.hooksPath=/dev/null clone --no-checkout https://github.com/OWASP/NodeGoat.git targets/nodegoat
git -C targets/nodegoat -c core.hooksPath=/dev/null checkout c5cb68a7084e4ae7dcc60e6a98768720a81841e8
chmod -R a-w targets/nodegoat
```

The pinned commit is recorded in `targets/targets.json`. Nothing in the target is installed or
executed.

## Build the SBOM and graph (D1.S3)

```bash
uv run --locked python -m guardian.sbom build --target nodegoat --out runs/d1s3
uv run --locked python -m guardian.sbom path --graph runs/d1s3/graph.json --package marked
```

## Vulnerability databases and feeds (D1.S2/D1.S4, about 5.3 GB in `cache/`)

```bash
W=$PWD
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home GRYPE_DB_CACHE_DIR=$W/cache/grype tools/bin/grype db update
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home tools/bin/trivy fs --download-db-only --cache-dir $W/cache/trivy
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=$W/cache/osv \
  tools/bin/osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
  -L $W/targets/nodegoat/package-lock.json --format json --output-file /dev/null || true
scripts/fetch_feeds.sh        # EPSS and CISA KEV into cache/feeds, with SHA-256 and date in feeds.json
```

Grype refuses databases older than 120 hours, so refresh the caches before a demo.

## Scanner-only baseline (D1.S4)

```bash
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s4
```

All scanners run in an empty network namespace (`unshare -rn`). The outputs in `runs/d1s4/`
are `findings.json`, `baseline.md`, `baseline.json`, and the raw `grype.json`, `trivy.json` and
`osv.json`.

## Base image for the image scan (D1.S5)

```bash
python3 -I scripts/fetch_image.py library/node 12-alpine   # Docker Hub only; every blob SHA-256-verified
```

This writes an OCI layout to `cache/images/library_node_12-alpine/` and records the digests in
`targets/images.json`. The baseline command then scans it offline. It also runs Hadolint,
`trivy config` and zizmor (`--offline --no-config`) on the Dockerfile and workflows.

## Popular-package list and seeded fork (D1.S6)

```bash
python3 -I scripts/fetch_toplist.py      # npm-high-impact 1.13.0, SHA-512 verified, read as text only
python3 -I scripts/seed_anomalies.py     # SYNTHETIC local fork targets/nodegoat-seeded (no remote)
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s6-clean
uv run --locked python -m guardian.scan baseline --target nodegoat-seeded --out runs/d1s6-seeded
uv run --locked python -m guardian.scan evaluate --seeded runs/d1s6-seeded --clean runs/d1s6-clean \
  --out runs/d1s6-seeded/evaluation.json
```

`seed_anomalies.py` rewrites the seeded fork and ground truth from scratch; the commit SHA stays
stable only while the script and base commit are unchanged. The seeded target's base image is
`node:latest`, which is not fetched, so its run has no image findings.

## Run the agents (agentic, goal driven)

```bash
export DEEPINFRA_API_KEY=...            # your key
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1
uv run --locked --extra llm-openai python -m guardian run --target nodegoat \
  --goal "Assess supply-chain risk and propose safe, verified remediations" \
  --budget-steps 100 --budget-tool-calls 250 --budget-seconds 900 --budget-tokens 1200000
uv run --locked python -m guardian trace  --agent-run <id> [--kinds plan tool_call delegate]
uv run --locked python -m guardian report --agent-run <id>
uv run --locked python -m guardian sandboxes
```

A supervisor plans, delegates to specialists (`inventory`, `vulnerability`, `forensics`,
`container_ci`, `risk`, `remediation`, `validation`, `verifier`), replans and stops on its
goal, a budget (steps, tool calls, seconds, tokens, optional USD) or a need for a human.
Prompts are in `prompts/`; every plan revision, tool call, delegation and decision is appended
to `agent_events` (append-only) in `runs/guardian.db`. Typical live run: 80-90 steps,
about 200 tool calls, 0.8-0.9M tokens, 7 to 8 minutes.

## Evidence UI

```bash
(cd ui && npm ci && npm run build)       # writes ui/dist
uv run --locked python -m guardian.api --port 8765   # loopback only, then open http://127.0.0.1:8765
```

Paste a GitHub URL to clone (read-only, nothing executed) and analyse it. Tabs: Overview,
Agent run (live plan, narration, tool calls, delegations, hypotheses, budget), Findings
(with confidence), Dependency graph, SBOM, **Remediation**, Report, Checklist.
The UI has been type-checked, built and API-tested; it has **not been viewed in a real browser**
in this environment (none available).

## Sandbox for untrusted code

Package code never runs on the host. `sandbox_exec` and the Day 2 build/test steps need a
container backend; without one they refuse (never fall back to the host).

- `docker`: `docker run --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --user 65534 --pull never`, read-only mounts, tmpfs noexec. Needs a running daemon and
  `GUARDIAN_SANDBOX_IMAGE`. The daemon could **not be started here** (not root, no `newuidmap` for rootless mode), so
  this path is covered by unit tests of the command builder only (**runtime unverified**).
- `bwrap` (bubblewrap, used for build and test): user/pid/net/ipc/uts namespaces, no network, no
  capabilities, read-only work tree, tmpfs scratch, no home, killed with its parent, rlimits.
  Needs no daemon and no root. Isolation properties are tested with real namespaces
  (`tests/test_sandbox.py`). `npm ci --ignore-scripts` is the only networked step and runs no
  package code.
- `sbx` (Docker Agent Sandboxes): detection only. Its network policy is global; a
  process-level recipe (`sbx policy init deny-all`, `sbx policy allow network api.deepinfra.com`)
  is **unverified** (WSL2 is not a documented platform).

## Day 2: prioritise, investigate, remediate, validate

```bash
# 1. agents propose (or let the goal include remediation); proposals are stored, never applied
# 2. a human reviews and decides, with a name that is logged with the time
uv run --locked python -m guardian approvals list     --run runs/<run-dir>
uv run --locked python -m guardian approvals show     --run runs/<run-dir> R-009
uv run --locked python -m guardian approvals approve  --run runs/<run-dir> R-009 --approver "Your Name" --note "ok"
# 3. validate the approved proposal on an isolated branch
GUARDIAN_ALLOW_REGISTRY_ACCESS=1 uv run --locked python -m guardian approvals validate --run runs/<run-dir> R-009
```

What validation does: copies the target to `targets/work/` (its own git repo, hooks off,
branch `guardian/fix-<finding>`), applies the approved `package.json` edit, regenerates the
lockfile with `npm install --package-lock-only --ignore-scripts` (clean environment, no
credentials), rescans offline with the same scanners as the original run, then diffs the SBOM
and findings and reports a verdict:

| Verdict | Meaning |
|---|---|
| `verified` | original finding gone, no new Critical/High, build and tests passed, SBOM diff explained |
| `partially_verified` | rescan clean, but build/tests did **not run** (reason recorded) or SBOM changed beyond the upgraded package |
| `failed` | finding remains, a new Critical/High appeared, or a build/test step failed |
| `blocked` | change not applied or not rescannable (e.g. registry access not allowed) |

Without a configured sandbox, build and tests are always `not_run`, so the best possible verdict
here is `partially_verified`. In the UI, the same flow is the Remediation tab (the API needs a
per-server token plus a loopback `Host`; agents have no approve tool and no route to the token).
The original target checkout is never written. Nothing is merged or pushed.

Prioritisation: severity, EPSS/KEV, reachability, exposure and provenance feed the PDF formula
(unknown factors renormalised, coverage shown). Each finding also carries a computed
**confidence** (scanner agreement, factor coverage, heuristic vs confirmed). Non-CVE
investigation uses `run_anomaly_rules`, `check_typosquat`, `inspect_lockfile_entry`,
`list_install_scripts` and `compare_lockfiles` (target vs its `base_target`, e.g. the seeded
fork `nodegoat-seeded` vs `nodegoat`); tools return facts and agents' reasoning is stored as
hypotheses ruled on by the verifier.

## Risk scoring and the evidence store (D1.S7)

The baseline command now also scores and ranks every finding, and saves the run to SQLite:

```bash
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s7
sqlite3 runs/guardian.db "SELECT id, risk_score, risk_level, weight_coverage, component_name \
  FROM findings WHERE run_id='runs/d1s7' ORDER BY ordinal LIMIT 10"
```

Store schema is v4 (v3 added agent runs, v4 adds proposals, approvals and validations;
older stores migrate additively). `baseline(..., db=None)` skips the store (the tests use this or their own database). The store
needs only Python's stdlib `sqlite3`; the `sqlite3` command line tool is optional.

## End-to-end demo (Prioritized Risk -> Fix -> Approval -> Build & Test -> Rescan -> Verdict)

```bash
python3 scripts/demo_remediation.py --allow-external-models --allow-registry   # asks you at the gate
python3 scripts/demo_remediation.py --allow-external-models --allow-registry --approve-as "Your Name"
```

It registers `demo/vulnerable-app` (two outdated dependencies, real build and tests), runs the
agents to propose fixes, **stops for your approval**, runs the validation agent, and prints the
verdicts from the evidence store. `--approve-as` means *you* approve everything under that name.

### Whole demo in the browser

```bash
scripts/run_demo.sh --ui      # starts the UI at http://127.0.0.1:8765 with the key and opt-ins set
```

Press **Run the demo app** (or paste a GitHub URL; choose the goal "Assess and propose fixes").
The header strip shows what the server can do (agents, npm registry, sandbox). The flow bar
tracks Prioritized risk -> Recommended fix -> Human approval -> Build, test, rescan -> Verified
remediation. The agents run live (Agent run tab), the UI jumps to **Remediation** when proposals
exist, you enter your name and **Approve**, then **Validate on a branch** and read the verdict.
Verified in a real browser (headless Chromium) on 2026-11-24: ~4 min to the approval gate;
approve and validate on the demo app took 47 s and returned *Verified*.

## Known limitations

- Build and test run in bubblewrap (host toolchain, read-only), not in a Docker image; Docker
  could not be started here. A suite that already fails on the unmodified copy is `not_run`,
  never evidence for the fix.
- Lockfile regeneration needs the npm registry (opt-in); without it validation is `blocked`.
- Image and CI proposals (`update_base_image`, `pin`) name what is missing (digest, commit SHA)
  rather than guessing; they are not auto-applicable.
- The model exposes no hidden reasoning; the UI shows narration, rationale and tool choices.
- Agent runs are non-deterministic; deterministic gates, not the model, enforce facts.
- Licenses are mostly "unspecified" in Syft output; no license policy is evaluated.
- UI not browser-verified; `sbx` and Docker sandbox runtime unverified.
