#!/usr/bin/env bash
# Run the gated LLM analysis through DeepInfra.
#
#   ./scripts/deepinfra_demo.sh [RUN_DIR] [LIMIT] [MODEL]
#
# The key is taken from DEEPINFRA_API_KEY, or from ~/.config/guardian/deepinfra.key when the
# environment variable is absent. The value is never printed, logged or written to the workspace.
# MODEL defaults to the provider default (deepseek-ai/DeepSeek-V4.1-Flash-1017).
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:-runs/demo}"
LIMIT="${2:-10}"
MODEL="${3:-}"
KEY_FILE="${HOME}/.config/guardian/deepinfra.key"

key="${DEEPINFRA_API_KEY:-}"
if [[ -z "$key" && -f "$KEY_FILE" ]]; then
  key="$(cat "$KEY_FILE")"
fi
if [[ -z "$key" ]]; then
  echo "No DeepInfra key. Set DEEPINFRA_API_KEY or write it to $KEY_FILE (chmod 600)." >&2
  exit 2
fi
if [[ ! -f "$RUN/baseline.json" ]]; then
  echo "No run at $RUN. Run: uv run --locked python -m guardian.scan baseline --target nodegoat --out $RUN" >&2
  exit 2
fi

uv sync --locked --extra llm-openai >/dev/null

echo "==> DeepInfra analysis of $RUN (model ${MODEL:-<provider default>}, limit $LIMIT)"
args=(--run "$RUN" --limit "$LIMIT" --provider deepinfra)
if [[ -n "$MODEL" ]]; then
  args+=(--model "$MODEL")
fi
DEEPINFRA_API_KEY="$key" GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.agents analyze "${args[@]}"
