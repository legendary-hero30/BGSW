# End-to-end demo in the browser

Every phase runs from the UI: **Prioritized risk -> Recommended fix -> Human approval ->
Build and test -> Rescan -> Verified remediation.** Agents assess the app and propose fixes; *you*
approve; the system applies the fix on an isolated branch, builds, tests, rescans and reports a
verdict. Nothing is merged or pushed.

Last verified in headless Chromium on 2026-11-24 (demo app): about 4 minutes from the button
to the approval gate, then 47 seconds from Approve to a **Verified** verdict.

## 1. One-time setup

Needs: Linux/WSL2, `uv`, Node and npm, `bubblewrap` (`/usr/bin/bwrap`), the pinned scanners and
vulnerability databases from [SETUP.md](SETUP.md), and a DeepInfra API key.

```bash
cd /home/suthekshan/bosch
uv sync --locked --extra llm-openai
(cd ui && npm ci && npm run build)        # builds ui/dist (skip if it already exists)

cp .env.example .env
chmod 600 .env
```

Edit `.env` and set your key (the file is git-ignored; never commit it):

```
DEEPINFRA_API_KEY=your-key-here
```

That is the only line you must fill in. The two opt-ins the demo needs
(`GUARDIAN_ALLOW_EXTERNAL_MODELS=1`, `GUARDIAN_ALLOW_REGISTRY_ACCESS=1`) are set by the launcher in
step 2. A real environment variable always overrides the `.env` value.

What the opt-ins mean: run metadata goes to DeepInfra (no secrets, no source trees), and npm may
contact registry.npmjs.org to regenerate the lockfile and install dependencies
(`--ignore-scripts`: no package code runs during install).

## 2. Start

```bash
scripts/run_demo.sh --ui
```

Open **http://127.0.0.1:8765**. (Without the script:
`GUARDIAN_ALLOW_EXTERNAL_MODELS=1 GUARDIAN_ALLOW_REGISTRY_ACCESS=1 uv run --locked --extra llm-openai python -m guardian.api --port 8765`.)

Under the form, three chips should be green: **Agents (DeepInfra)**, **Validation (npm registry)**,
**Build/test sandbox**. An amber chip says exactly what is missing.

## 3. Walk through the phases

| # | You do | You see |
|---|---|---|
| 1 | Press **Run the demo app** (goal: *Assess and propose fixes*). To use your own repo, paste a GitHub URL instead. | A banner: Clone -> Agents at work -> Done. The page jumps to **Agent run**. |
| 2 | Watch **Agent run**. | Live plan, each agent's narration, tool calls and arguments, delegations to specialists (inventory, vulnerability, forensics, container/CI, risk, remediation, verifier), hypotheses and the verifier's rulings, gate rejections, and a budget meter. |
| 3 | Open **Findings**, **Dependency graph**, **SBOM** (optional). | Ranked findings with the score breakdown and a *confidence* level, the path from the app to a vulnerable package, the CycloneDX component list. |
| 4 | Wait for the run to finish (about 4 minutes). | The UI switches to **Remediation** by itself. The flow bar shows steps 1-2 done and step 3 (Human approval) current. |
| 5 | Read a proposal, e.g. `R-001: minimist 1.2.5 -> 1.2.6`. | Expected risk reduction, compatibility impact, rollback, alternatives considered, the exact `package.json` edit, and the agent's justification (labelled as inference). |
| 6 | Type **your name**, optionally a note, press **Approve**. | The approval is logged with your name, the time and a hash of this exact proposal. Agents cannot approve. |
| 7 | Press **Validate on a branch**. | A progress line while it works: isolated copy and branch -> lockfile regenerated -> offline rescan -> build and tests in the sandbox. About 1 minute. |
| 8 | Read the **Validation report**. | Verdict (**Verified** / Partially verified / Failed / Blocked), step results (build, tests, lockfile, rescan), risk before -> after, resolved / remaining / new findings, SBOM diff, the patch diff and the final confidence. |

Repeat 5-8 for the second proposal (`underscore -> 1.13.8`). Each is validated on its own, so the
other package's finding still shows as *remaining* in that report.

### What the verdicts mean

- **Verified**: the original finding is gone, no new Critical/High finding, build and tests passed, SBOM changes explained.
- **Partially verified**: rescan clean but build/tests did not run (reason shown) or the SBOM changed beyond the upgraded package.
- **Failed**: the finding remains, a new Critical/High appeared, or build/tests failed *and passed before the change*.
- **Blocked**: the change could not be applied or rescanned (for example registry access not allowed).

A test suite that already fails on the unmodified copy is reported as *not run*, never as proof for the fix.

## Modes: public repo vs your own repo

The form has two modes.

- **Public repo**: analyse and recommend. Fixes can be approved and validated on an isolated branch, but there is no push option.
- **My repo**: the same, plus a **Prepare push** button on a *verified* or *partially verified* fix. It writes a patch and prints one command:

```bash
scripts/push_fix.sh runs/<run>/exports/R-001.json
```

You run that command yourself, with your own git login (credential helper, ssh agent or `gh auth`). It shows the diff, asks you to type `owner/repo`, then pushes a new `guardian/fix-*` branch and prints the pull-request link. It checks the patch hash, refuses the default branch, never forces and never merges. By default Guardian itself holds no token and never contacts your repository.

**Optional: let the server push.** In `.env` set `GUARDIAN_ALLOW_PUSH=1` and `GUARDIAN_GITHUB_TOKEN=<token>` (a fine-grained token limited to that one repository, *Contents: read and write* only), then restart. A **Push branch** button then appears after **Prepare push**; you must type `owner/repo` to confirm. It still pushes only a new `guardian/fix-*` branch, never forces, never merges and never opens the pull request. The token is read only at push time and never logged. Never paste the token into the chat or the UI. Private repositories cannot be cloned by the server (it has no login), so use a public one or a fork.

## 4. Other ways to run it

```bash
scripts/run_demo.sh                       # same flow in the terminal; stops at the approval gate
scripts/run_demo.sh --approve-as "Name"   # YOU approve every applicable proposal as "Name"
python -m guardian approvals list --run runs/<run-dir>        # approve/reject/validate by CLI
python -m guardian trace --agent-run <id>                     # full audit trail of an agent run
```

## 5. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Amber **Agents** chip, run is "scanner-only" | `DEEPINFRA_API_KEY` missing or empty in `.env`. Restart the server after editing it. |
| `401 User is not authorized` in the Agent run tab | The key is wrong, rotated or revoked. Put the current key in `.env` and restart the server (a running server keeps the old one). |
| Amber **Validation** chip / Validate button disabled | Start with `scripts/run_demo.sh --ui` (it sets `GUARDIAN_ALLOW_REGISTRY_ACCESS=1`). |
| Amber **Build/test sandbox** chip | `bubblewrap` is missing or user namespaces are disabled. Verdicts are then at best *partially verified*. |
| Verdict **Blocked** | Read the reason in the report; usually registry access or an npm error. |
| `warning: .env is readable by other users` | `chmod 600 .env`. |
| A run shows as *interrupted* | Its process ended without closing the record (for example the server was stopped). Start a new run. |

## 6. What is real and what is limited

- Real: live DeepSeek agents via DeepInfra, real scanners (Syft, Grype, Trivy, OSV-Scanner) run offline, real lockfile regeneration, real build and tests, a real rescan and SBOM diff.
- Build and tests run in a **bubblewrap** sandbox (no network, no capabilities, read-only tree). Docker could not be started in the development environment, so the Docker backend is unit-tested only.
- Agent output varies run to run (the supervisor may phrase or order things differently); the facts come from tools, and deterministic gates reject unsupported claims.
- The demo app is small and deliberately risky (`demo/vulnerable-app`): 7 outdated npm packages (40 CVEs across axios, lodash, ejs, jsonwebtoken, node-fetch, minimist, underscore), a vendored `colour-utils` package with an install script, an unsafe `Dockerfile` and an unsafe `.github/workflows/ci.yml` (about 59 findings in an offline scan). On large repositories the build/test step depends on the repository having working `build` and `test` scripts that need no network or database.
- The UI was checked at desktop width only.
