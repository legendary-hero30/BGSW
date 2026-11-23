# Software Supply Chain Guardian

**Know what you build. Trust what you ship.**

An evidence-first, agentic supply-chain risk guardian. It scans a real open-source application
and its container/CI context, correlates findings with reachability, exposure and provenance,
scores and ranks them, and has an LLM explain each finding **only from stored tool output**. Every
claim is gated: identifiers, versions, paths and evidence citations must already belong to the
finding, or the explanation is rejected and sent back to the model.

Day 1 answers the checkpoint: *"Show us what is in the application, what changed, and what appears
risky."* Day 2 (patch proposal, human approval, rebuild, rescan) is not part of this build.

---

## What runs (Steps 1-9)

| Step | Module | What it does |
|---|---|---|
| 1. Contracts | `guardian.schemas`, `guardian.scoring` | Frozen Pydantic schemas for evidence, SBOM, graph, risk and findings; the PDF risk formula |
| 2. Scanners and sample app | `scripts/`, `tools/`, `targets/` | Pinned Syft, Grype, OSV-Scanner, Trivy, Hadolint, zizmor; OWASP NodeGoat pinned by commit |
| 3. Discovery | `guardian.sbom` | CycloneDX 1.5 SBOM, npm lockfile resolution, dependency graph, path queries |
| 4. Detection | `guardian.scan.baseline` | Grype + Trivy + OSV-Scanner correlated by advisory alias, EPSS/KEV enrichment, citation verifier |
| 5. Image and CI/CD | `guardian.scan.posture` | Base image scan (OCI layout), Dockerfile rules, zizmor/Hadolint, unpinned-image and unpinned-CI findings |
| 6. Anomalies | `guardian.scan.anomaly` | Typosquats, install scripts, lockfile integrity/host changes, unexpected dependency additions, seeded-fork evaluation |
| 7. Prioritization | `guardian.scan.context`, `guardian.store` | Reachability, exposure, provenance, risk score v1, SQLite evidence store |
| 8. Agents | `guardian.agents` | LangChain Deep Agents orchestrator with discovery/detection/analysis subagents, tool allow-lists, prompt-injection rules and the deterministic explanation gate |
| 9. Evidence and agent view | `guardian.api`, `ui/` | FastAPI over the store, evidence cards, Cytoscape path highlight, the recorded agent steps, and a GitHub repository input that clones and scans a new repo |

The LLM is only used for the per-finding explanation (Step 8), and that explanation is rendered in
the Step 9 evidence card. No finding, CVE, version, path or score is invented by the model.
Scanners and rules are deterministic by design: the PDF requires deterministic tools to produce
facts and the model to reason over them. The model's decision is which facts matter, how to
explain them, how reachable they are and how confident to be; a deterministic gate checks the
result.

---

## Quick start

Requirements: Linux, `uv` (0.13+), Python 3.12 (uv supplies it), Node 20+ (only to rebuild the
UI). The pinned scanner binaries and vulnerability databases are already reproduced by the setup
scripts below.

```bash
cd /home/suthekshan/bosch

# 1. Python environment (creates .venv, installs the locked set)
uv sync --locked --extra llm-openai

# 2. Pinned scanners (downloads ~240 MB, verifies SHA-256) - only if tools/bin is absent
uv run --locked python scripts/install_tools.py

# 3. Sample app (only if targets/nodegoat is absent)
git -c core.hooksPath=/dev/null clone https://github.com/OWASP/NodeGoat.git targets/nodegoat
git -C targets/nodegoat -c core.hooksPath=/dev/null checkout c5cb68a7084e4ae7dcc60e6a98768720a81841e8
chmod -R a-w targets/nodegoat

# 4. UI build (served by the API)
cd ui && npm ci && npm run build && cd ..

# 5. DeepInfra key (outside the workspace; never commit it)
mkdir -p ~/.config/guardian && chmod 700 ~/.config/guardian
printf '%s' '<key>' > ~/.config/guardian/deepinfra.key && chmod 600 ~/.config/guardian/deepinfra.key

# 6. One-command demo: scan (if needed), explain with DeepInfra, then serve the API + UI
make demo
```

Open <http://127.0.0.1:8000/>. The UI lists stored runs, findings ranked by risk, evidence cards,
the recorded **Agent steps**, and a box where you can paste a GitHub repository to scan.

### Manual pipeline (same thing, step by step)

```bash
# Discovery + detection + scoring + store
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/demo

# Live, gated explanations through DeepInfra
DEEPINFRA_API_KEY="$(cat ~/.config/guardian/deepinfra.key)" \
  GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.agents analyze --run runs/demo --limit 10

# API + built UI
DEEPINFRA_API_KEY="$(cat ~/.config/guardian/deepinfra.key)" \
  GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.api --port 8000
```

---

## Model configuration

All model access goes through `guardian.agents.models.build_model`. **Every run uses a live
model**; there is no offline/template model in the product. External calls are off by default and
require:

```bash
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1
```

Keys are read by each provider SDK from its own environment variable and are never read, logged or
stored by Guardian. Set them outside the repository.

| `--provider` | Package (extra) | Key |
|---|---|---|
| `deepinfra` (default) | `langchain-openai` (`--extra llm-openai`) | `DEEPINFRA_API_KEY`; default model `deepseek-ai/DeepSeek-V4.1-Flash-1017` |
| `openai` | `langchain-openai` (`--extra llm-openai`) | `OPENAI_API_KEY` |
| `openai_compatible` | `langchain-openai` (`--extra llm-openai`) | `OPENAI_API_KEY` (any value for a local server) + `--base-url` |
| `anthropic` | `langchain-anthropic` (installed) | `ANTHROPIC_API_KEY` |
| `google_genai` | `langchain-google-genai` (installed) | `GOOGLE_API_KEY` |
| `deepseek` | `langchain-deepseek` (needs approval) | `DEEPSEEK_API_KEY` |
| `ollama` | `langchain-ollama` (needs approval) | none, local |

A local Ollama server can be used without the `langchain-ollama` package through its
OpenAI-compatible endpoint:

```bash
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1 OPENAI_API_KEY=ollama
uv run --locked python -m guardian.agents analyze --run runs/demo --limit 3 \
  --provider openai_compatible --base-url http://127.0.0.1:11434/v1 --model qwen2.5:3b
```

With the DeepInfra key reachable (environment variable or
`~/.config/guardian/deepinfra.key`), the live, gated analysis is one command:

```bash
make deepinfra                       # runs/demo, 10 findings, DeepSeek V4.1 Flash
./scripts/deepinfra_demo.sh runs/demo 10 Qwen/Qwen3-32B   # override the model
```

---

## Sample input and expected output

**Input:** `targets/targets.json` registers OWASP NodeGoat at commit
`c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (Apache-2.0, npm lockfile v2), plus a clearly labelled
synthetic fork `nodegoat-seeded` with inert seeded anomalies. The UI box also accepts any public
GitHub npm repository with `package-lock.json` v2/v3; Guardian clones it depth-1 and read-only.

**A real run** (`runs/OWASP__NodeGoat-20261123T125015Z/`, databases of 2026-11-23) produced:

- CycloneDX 1.5 SBOM with 422 components and a graph of 1,480 nodes / 2,295 edges.
- 415 findings: 393 vulnerabilities (dependency + image), 1 confirmed malicious package
  (`fsevents@1.2.9`, MAL-2023-462), 8 unpinned/unsafe CI findings, 3 untrusted-image findings,
  2 misconfigurations and 8 anomaly findings (typosquats, install scripts, lockfile change).
- Risk bands: Critical 1 (forced malicious override), Medium 97, Low 317.
- Citation verifier: 10,127 / 10,127 cited facts resolve to raw tool output (100%).
- After the DeepInfra analysis, `explanations.json` lists the accepted gated explanations and
  `agent-trace.json` the tool calls shown in the Agent steps view.
- **Live DeepInfra run:** `deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017` produced **10 accepted
  explanations, 1 rejected attempt, 0 blocked tool calls and 13 tool calls** (`task(analysis)` +
  `list_findings` + 10× `get_finding` + `submit_explanations`). The rejected attempt named an
  advisory that was not attached to its finding, which the gate refused.
- **Live UI flow:** pasting `https://github.com/isaacs/node-lru-cache` into the repository box
  completed clone → scan → analysis with **74 findings, 10 accepted, 1 rejected and 14 tool
  calls**, and the job's live step list updated as each tool call landed.

Expected files in a run directory:

```
baseline.json  baseline.md  findings.json  graph.json  sbom.cdx.json
grype.json  trivy.json  osv.json  grype-image.json  trivy-image.json
hadolint.json  zizmor.json  trivy-config.json
explanations.json  explanations.md  agent-trace.json   # after the agents run
```

The same data is in the SQLite store (`runs/guardian.db`) and is what the API/UI serve.

---

## Demo script (about 5 minutes)

1. `make demo` starts the API at <http://127.0.0.1:8000/>.
2. **Scan a new repository:** paste `https://github.com/owner/repository` into the box and press
   *Scan repository*. The banner shows clone → scan → DeepInfra analysis, with each agent tool
   call appearing live.
3. **What is in the application:** pick a run, sort by risk, open a transitive finding. The card
   shows the component, purl, dependency path, highlighted graph and the five risk factors.
4. **What changed:** switch to the `runs/d1s7-seeded` run and open a typosquat or lockfile-change
   finding. The seeded fork is labelled SYNTHETIC.
5. **What appears risky:** open `fsevents@1.2.9` (forced Critical) and the top imported CVE
   (`underscore@1.9.1`) and read the evidence rows and the DeepInfra explanation.
6. **Agent steps:** open the *Agent steps* tab. It shows the orchestrator's `task` delegation and
   every `list_findings`, `get_finding` and `submit_explanations` call, the gate's accepted /
   rejected counts and the final message.

The same data is available as JSON:

```bash
curl -s "http://127.0.0.1:8000/api/agent-steps?run=runs/demo" | python3 -m json.tool
```

---

## Project layout

```
src/guardian/schemas/    frozen Pydantic contracts (evidence, SBOM, graph, risk, findings)
src/guardian/scoring/    PDF risk formula, bands, malicious override
src/guardian/sbom/       Syft invocation, CycloneDX writer, npm lockfile graph
src/guardian/scan/       scanners, parsers, correlation, anomaly rules, posture, risk context,
                         verifier, seeded evaluation
src/guardian/agents/     Deep Agents orchestrator, subagents, tools, gate, live providers
src/guardian/store.py    SQLite evidence store (runs, evidence, findings, graph, explanations)
src/guardian/api/        FastAPI app, CLI and the repository-scan job
src/guardian/targets.py  GitHub URL validation, read-only clone and dynamic target registry
src/guardian/checklist.py PDF self-checklist, still exposed at /api/checklist for audits
ui/                      React + TypeScript + Tailwind + Cytoscape evidence and agent-step UI
scripts/                 tool installer, feed/image/toplist fetch, seeded fork, demo runner
tests/                   unit, contract, anomaly, agent, API, job and offline integration tests
```

## Tests and validation

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest                     # unit + contract + API tests
uv run --locked pytest -m integration      # real offline scanners on the pinned target
```

The integration tests need `tools/bin/` and `targets/nodegoat/`. They run every scanner inside an
empty network namespace (`unshare -rn`), so they work with the network off.

## Security and responsible AI

- Deterministic tools produce facts; the model only explains them. The gate (`agents/gate.py`)
  rejects any explanation that cites evidence, advisories, package versions or reachability that
  the finding does not already contain.
- Repository content and scanner excerpts are returned to the model as `untrusted_excerpt`,
  labelled as data, never as instructions. Tools are allow-listed per agent; the orchestrator can
  only call `task` and the in-state `read_file`.
- The API is loopback-only, opens SQLite with `mode=ro`, sets a strict CSP and refuses every write
  except the single `POST /api/runs` that starts a repository scan. No CORS.
- The GitHub input accepts only `https://github.com/<owner>/<repo>`; the clone uses fixed argv,
  depth 1, no tags, no hooks, no LFS smudge, no submodules, symlinks disabled, a 5-minute timeout,
  a 1 GiB working-tree cap, a pinned commit and a read-only checkout. Nothing is executed.
- Scans run offline inside an empty network namespace. No secrets are read, logged or stored. The
  only secret is the provider API key, held in an environment variable outside the workspace.
- No patch is applied, merged, deployed or published anywhere in this build.

## Known limitations

- Day 2 (remediation, human approval, rebuild/rescan, before-after report) is out of scope; the
  evidence card marks those rows as Day 2.
- Reachability is import-level, not a call graph, so "called" is never claimed.
- Provenance `0` means "no signal from the implemented checks", not verified trust.
- NodeGoat's own built image is not scanned because the Docker daemon is unavailable; the
  Dockerfile's base image (`node:12-alpine`) is pulled by digest and scanned instead.
- Grype CPE-only image matches are excluded (documented in `DECISIONS.md` D5-03).
- Exact finding counts drift as vulnerability databases update.
- The repository input supports public npm projects with `package-lock.json` v2/v3 only. Private
  repos, submodules and non-npm ecosystems are not supported. A dynamic repo's base image is only
  scanned when it is already in the local OCI cache.
- A live DeepInfra run needs the key; the scan and all deterministic findings still complete
  without it, and the Agent steps view says the analysis has not run.

See `RUN.md` for the operational runbook, `SETUP.md` for environment reproduction, `DECISIONS.md`
for every design choice and `TEST_RESULTS.md` for measured results.
