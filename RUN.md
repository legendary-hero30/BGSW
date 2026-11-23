# RUN.md: operational runbook

Everything runs locally. No cloud service is required except an optional LLM provider. Scanners
run offline in an empty network namespace.

## 0. Prerequisites

| Need | Check | Notes |
|---|---|---|
| `uv` | `uv --version` | Installs Python 3.12 and the locked environment |
| Node 20+ | `node --version` | Only to rebuild `ui/`; the built files are already in `ui/dist` |
| `git` | `git --version` | Only to clone the sample target |
| `unshare` | `unshare -rn true` | Used to run scanners with no network |
| Docker | *not required* | The base image is pulled as an OCI layout without a daemon |

```bash
cd /home/suthekshan/bosch
uv sync --locked --extra llm-openai
```

## 1. Reproduce the scanners and the target

```bash
python3 -I scripts/install_tools.py     # pinned binaries, SHA-256 verified
git -c core.hooksPath=/dev/null clone https://github.com/OWASP/NodeGoat.git targets/nodegoat
git -C targets/nodegoat -c core.hooksPath=/dev/null checkout c5cb68a7084e4ae7dcc60e6a98768720a81841e8
chmod -R a-w targets/nodegoat
```

Vulnerability databases, EPSS and KEV are cached under `cache/` (about 5.3 GB). Refresh them
before a demo because Grype refuses databases older than 120 hours:

```bash
W=$PWD
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home GRYPE_DB_CACHE_DIR=$W/cache/grype \
  tools/bin/grype db update
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home \
  tools/bin/trivy fs --download-db-only --cache-dir $W/cache/trivy
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home \
  OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=$W/cache/osv \
  tools/bin/osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
  -L $W/targets/nodegoat/package-lock.json --format json --output-file /dev/null || true
scripts/fetch_feeds.sh
```

The base image is fetched by digest into an OCI layout (no Docker daemon):

```bash
python3 -I scripts/fetch_image.py library/node 12-alpine
```

## 2. Run the pipeline

Every run uses a live model. DeepInfra is the configured provider and its default model is
`deepseek-ai/DeepSeek-V4.1-Flash-1017`.

```bash
# Discovery + detection + scoring + SQLite store
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/demo

# Live, gated explanations through DeepInfra
DEEPINFRA_API_KEY=... GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.agents analyze --run runs/demo --limit 10 \
  --provider deepinfra
```

If the key is not in the session environment, keep it outside the workspace in a mode-600 file and
read it only for the command:
`DEEPINFRA_API_KEY="$(cat ~/.config/guardian/deepinfra.key)" GUARDIAN_ALLOW_EXTERNAL_MODELS=1 ...`.

`make deepinfra` (or `./scripts/deepinfra_demo.sh [RUN] [LIMIT] [MODEL]`) does the same and reads
the key from either place.

The full agentic path (discovery -> detection -> analysis) is one command:

```bash
DEEPINFRA_API_KEY=... GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.agents run --target nodegoat --out runs/demo \
  --provider deepinfra
```

## 3. Serve the evidence and agent view

```bash
DEEPINFRA_API_KEY=... GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.api --host 127.0.0.1 --port 8000 --db runs/guardian.db
```

Open <http://127.0.0.1:8000/>. The UI has a *Findings* tab with evidence cards and an *Agent steps*
tab with the recorded tool calls. The repository box at the top starts a new scan. The API refuses
any host other than loopback and every write except `POST /api/runs`. Useful endpoints:

```
GET  /api/runs
GET  /api/summary?run=runs/demo
GET  /api/findings?run=runs/demo&type=vulnerable_transitive&level=Medium&q=lodash
GET  /api/findings/F-001?run=runs/demo
GET  /api/graph/F-001?run=runs/demo
GET  /api/agent-steps?run=runs/demo
GET  /api/checklist?run=runs/demo
GET  /api/docs
POST /api/runs            {"repo": "https://github.com/owner/repository"}
GET  /api/jobs/{job_id}
```

`POST /api/runs` accepts only `https://github.com/<owner>/<repo>` for a public npm project with
`package-lock.json` v2/v3. It clones into `targets/dynamic/`, pins the commit, scans offline and
then runs the DeepInfra analysis. The job endpoint reports each phase and the live tool calls.

Rebuild the UI after changing `ui/src`:

```bash
cd ui && npm ci && npm run build && cd ..
```

## 4. One-command demo

```bash
make demo
```

`make demo` reads `DEEPINFRA_API_KEY` or `~/.config/guardian/deepinfra.key`, runs the baseline only
if `runs/demo/baseline.json` is missing, runs the live analysis, then serves the API and UI. It
refuses to start without a key: there is no offline model fallback.

## 5. Run the checks

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m "not integration"
uv run --locked pytest -m integration
```

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `refused: external model calls are disabled` | Set `GUARDIAN_ALLOW_EXTERNAL_MODELS=1` after authorizing the provider |
| `provider package ... is not installed` | Install the matching extra, e.g. `uv sync --extra llm-openai`, or use `openai_compatible` against a local server |
| `Missing credentials` from the OpenAI client | Set the provider key (`OPENAI_API_KEY`; any value for a local Ollama endpoint) |
| `no store at runs/guardian.db` | Run the baseline first; it creates the store |
| `store schema N != expected 2` | Use the current code; an old incompatible database must be regenerated |
| Grype `database is too old` | Refresh the Grype DB (120-hour limit) |
| `unknown run` from the API | The run ID is the workspace-relative output directory, e.g. `runs/demo` |
| Port 8000 busy | `--port 8010` |
| Scanners fail with `unshare` errors | The kernel must allow user namespaces; otherwise run the scanner CLIs directly is not supported by this build |
| UI shows only JSON | `ui/dist/index.html` is missing; rebuild the UI |

## 7. Safety

- Do not commit `.env` files or keys. The workspace `.gitignore` blocks `.env`, `*.pem` and
  `*.key`.
- The sample app is read-only and pinned by commit. Nothing is installed or executed from it.
- The synthetic fork (`targets/nodegoat-seeded`) is labelled SYNTHETIC and has no remote.
- Scanners run with a fixed environment, an argument allow-list, a path jail and offline
  network namespaces.
