# Setup

## Requirements

- `uv` 0.13.9, installed at `~/.local/bin/uv`.
- Python 3.12. `uv` provides it (cpython 3.12.16). The system `python3` is 3.14 and is not used.

## Reproduce the environment

```bash
cd /home/suthekshan/bosch
uv sync --locked          # creates .venv with Python 3.12.16 and installs uv.lock
uv run --locked pytest    # run tests
uv run --locked ruff check .
uv run --locked ruff format --check .
```

## Resolved dependencies (uv.lock, 2026-11-23)

Since D1.S9 the lock has 73 packages. It includes deepagents 0.7.38, langchain 1.5.0,
langchain-core 1.8.1, langgraph 1.2.22, langchain-anthropic 1.7.10, langchain-google-genai
4.5.0, langsmith 0.14.17, fastapi 0.163.1, uvicorn 0.54.0, and the optional `llm-openai` extra
(`langchain-openai` 1.8.0, `openai` 3.51.0, `tiktoken`, `regex`) used by DeepInfra. Everything is
resolved with `exclude-newer = 2026-11-16`. That cutoff moved pydantic to 2.14.3 and ruff to
0.17.5. The table below is the original D0/D1.S1 set.

| Package | Version | Role |
|---|---|---|
| pydantic | 2.14.4 | Contract validation (runtime) |
| pydantic-core | 2.50.5 | Pydantic dependency |
| annotated-types | 0.8.0 | Pydantic dependency |
| typing-extensions | 4.16.0 | Pydantic dependency |
| typing-inspection | 0.4.5 | Pydantic dependency |
| pytest | 9.2.0 | Tests (dev) |
| iniconfig, packaging, pluggy, pygments | 2.3.1, 26.3, 1.7.0, 2.21.0 | pytest dependencies (dev) |
| ruff | 0.17.6 | Lint and format (dev) |

Install the DeepInfra/OpenAI-compatible client with `uv sync --locked --extra llm-openai` (the
default `uv sync --locked` leaves it out). Scanner binaries are listed below.

## Secrets

No secrets are used. A future LLM API key goes in an environment variable outside the
workspace. `.env` files are git-ignored and must not be created in the workspace.

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

## Risk scoring and the evidence store (D1.S7)

The baseline command now also scores and ranks every finding, and saves the run to SQLite:

```bash
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s7
sqlite3 runs/guardian.db "SELECT id, risk_score, risk_level, weight_coverage, component_name \
  FROM findings WHERE run_id='runs/d1s7' ORDER BY ordinal LIMIT 10"
```

`baseline(..., db=None)` skips the store (the tests use this or their own database). The store
needs only Python's stdlib `sqlite3`; the `sqlite3` command line tool is optional.

## Agents (D1.S8) and the evidence view (D1.S9)

```bash
uv sync --locked --extra llm-openai   # deepagents, LangChain, FastAPI, DeepInfra client
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1 DEEPINFRA_API_KEY=...
uv run --locked python -m guardian.agents analyze --run runs/demo --limit 10
uv run --locked python -m guardian.agents run --target nodegoat --out runs/demo
uv run --locked python -m guardian.api --port 8000
```

Every run uses a live model; there is no offline/scripted model. DeepInfra is the provider
(`--provider deepinfra`, `DEEPINFRA_API_KEY`, default model
`deepseek-ai/DeepSeek-V4.1-Flash-1017`); the opt-in and data-handling policy are in
`LLM_PROVIDERS.md`. The API serves `ui/dist`, refuses non-loopback hosts and exposes one write
endpoint (`POST /api/runs`) for the GitHub repository box. Rebuild the UI with
`cd ui && npm ci && npm run build`.

## Not yet set up

- The Docker daemon. The CLI exists, but `/var/run/docker.sock` is missing. NodeGoat's own
  image cannot be built until it runs; the base image is scanned instead.
