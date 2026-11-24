#!/usr/bin/env bash
# One-command remediation demo: assess -> propose -> human approval -> build/test -> rescan -> verdict.
#
#   scripts/run_demo.sh                      # stops at the approval gate and asks you
#   scripts/run_demo.sh --approve-as "Name"  # YOU approve all applicable proposals as "Name"
#   scripts/run_demo.sh --serve              # afterwards, open the UI (Remediation tab)
#   scripts/run_demo.sh --ui                 # ALL phases in the browser: click "Run the demo app"
#
# Opt-ins this script sets for you (read them first): it sends run metadata to DeepInfra and lets
# npm reach registry.npmjs.org for the lockfile/install steps. Nothing is merged or pushed.
set -euo pipefail
cd "$(dirname "$0")/.."

SERVE=0
UI=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --serve) SERVE=1 ;;
    --ui) UI=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

fail() { echo "error: $*" >&2; exit 2; }
command -v uv >/dev/null   || fail "uv is not installed"
command -v node >/dev/null || fail "node is not installed"
command -v npm >/dev/null  || fail "npm is not installed"
[ -x /usr/bin/bwrap ]      || fail "bubblewrap (/usr/bin/bwrap) is needed for the build/test sandbox"
[ -x tools/bin/syft ] && [ -x tools/bin/grype ] || fail "scanners missing: python3 -I scripts/install_tools.py"
[ -d cache/grype ]         || fail "vulnerability databases missing (see SETUP.md)"
if [ -z "${DEEPINFRA_API_KEY:-}" ] && ! grep -qE '^(export )?DEEPINFRA_API_KEY=.+' .env 2>/dev/null \
   && [ ! -s "$HOME/.config/guardian/deepinfra.key" ]; then
  fail "no DeepInfra key: put DEEPINFRA_API_KEY=... in .env (see .env.example)"
fi

uv sync --locked --extra llm-openai >/dev/null

if [ "$UI" = 1 ]; then
  # the API server reads the key from .env itself; the opt-ins below are what this demo needs
  export GUARDIAN_ALLOW_EXTERNAL_MODELS=1 GUARDIAN_ALLOW_REGISTRY_ACCESS=1
  [ -d ui/dist ] || (cd ui && npm ci && npm run build)
  echo "Open http://127.0.0.1:8765 and press 'Run the demo app'. Approving is done by you, in the Remediation tab."
  exec uv run --locked --extra llm-openai python -m guardian.api --port 8765
fi

uv run --locked --extra llm-openai python scripts/demo_remediation.py \
  --allow-external-models --allow-registry "${ARGS[@]}"

if [ "$SERVE" = 1 ]; then
  [ -d ui/dist ] || (cd ui && npm ci && npm run build)
  echo "UI: http://127.0.0.1:8765  (Remediation tab)"
  exec uv run --locked python -m guardian.api --port 8765
fi
