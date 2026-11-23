#!/usr/bin/env bash
# One-command Guardian demo: discover/detect if needed, explain with DeepInfra, then serve.
#
#   ./scripts/demo.sh [RUN_DIR]
#
# Environment (all optional):
#   DEEPINFRA_API_KEY   required; alternatively ~/.config/guardian/deepinfra.key
#   GUARDIAN_MODEL      DeepInfra model id (default: provider default, DeepSeek V4.1 Flash)
#   GUARDIAN_LIMIT      findings to explain (default 10)
#   GUARDIAN_PORT       API port (default 8000)
#   GUARDIAN_TARGET     target name (default nodegoat)
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:-runs/demo}"
TARGET="${GUARDIAN_TARGET:-nodegoat}"
MODEL="${GUARDIAN_MODEL:-}"
LIMIT="${GUARDIAN_LIMIT:-10}"
PORT="${GUARDIAN_PORT:-8000}"
KEY_FILE="${HOME}/.config/guardian/deepinfra.key"

key="${DEEPINFRA_API_KEY:-}"
if [[ -z "$key" && -f "$KEY_FILE" ]]; then
  key="$(cat "$KEY_FILE")"
fi
if [[ -z "$key" ]]; then
  echo "No DeepInfra key. Set DEEPINFRA_API_KEY or write it to $KEY_FILE (chmod 600)." >&2
  exit 2
fi
export DEEPINFRA_API_KEY="$key"
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1

echo "==> syncing the locked environment (DeepInfra client)"
uv sync --locked --extra llm-openai >/dev/null

if [[ ! -x tools/bin/syft ]]; then
  echo "==> scanners missing: python3 -I scripts/install_tools.py" >&2
  exit 1
fi
if [[ ! -d ui/dist ]]; then
  echo "==> UI not built: cd ui && npm ci && npm run build" >&2
  exit 1
fi

if [[ ! -f "$RUN/baseline.json" ]]; then
  echo "==> discovery + detection + scoring -> $RUN"
  uv run --locked python -m guardian.scan baseline --target "$TARGET" --out "$RUN"
else
  echo "==> reusing existing $RUN/baseline.json"
fi

echo "==> explanations: provider=deepinfra model=${MODEL:-<provider default>} (limit $LIMIT)"
args=(--run "$RUN" --limit "$LIMIT" --provider deepinfra)
if [[ -n "$MODEL" ]]; then
  args+=(--model "$MODEL")
fi
uv run --locked python -m guardian.agents analyze "${args[@]}"

echo "==> serving the evidence view on http://127.0.0.1:$PORT/ (Ctrl-C to stop)"
exec uv run --locked python -m guardian.api --host 127.0.0.1 --port "$PORT"
