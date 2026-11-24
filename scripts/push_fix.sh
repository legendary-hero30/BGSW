#!/usr/bin/env bash
# Push one approved, validated Guardian fix to YOUR repository as a NEW BRANCH. You run this.
#
#   scripts/push_fix.sh runs/<run>/exports/R-001.json
#
# - Uses your own git credentials (credential helper, ssh agent or `gh auth`). Guardian never
#   sees them and never stores a token.
# - Pushes only a new branch named guardian/fix-*. It refuses the default branch, never forces
#   and never merges. You open the pull request and a person merges it.
# - Verifies the patch hash, clones fresh, applies the patch and shows the diff first.
set -euo pipefail
META="${1:?usage: scripts/push_fix.sh runs/<run>/exports/<proposal>.json}"
[ -f "$META" ] || { echo "no such file: $META" >&2; exit 2; }
DIR="$(cd "$(dirname "$META")" && pwd)"
get() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$META" "$1"; }
REPO="$(get repo)"; BRANCH="$(get branch)"; TITLE="$(get title)"; BASE="$(get base_commit)"
SHA="$(get patch_sha256)"; PATCH="$DIR/$(basename "$META" .json).patch"
[[ "$REPO" =~ ^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || { echo "refusing repo: $REPO" >&2; exit 2; }
[[ "$BRANCH" =~ ^guardian/fix-[a-z0-9._-]+$ ]] || { echo "refusing branch: $BRANCH" >&2; exit 2; }
[ "$(sha256sum "$PATCH" | cut -d' ' -f1)" = "$SHA" ] || { echo "patch hash mismatch: the patch changed after approval" >&2; exit 2; }

echo "Repository : $REPO"
echo "New branch : $BRANCH"
echo "Fix        : $TITLE"
echo "Approved by: $(get approved_by) at $(get approved_at)   verdict: $(get verdict)"
[ "$(get lockfile_origin)" = "repository" ] || echo "NOTE: the lockfile was $(get lockfile_origin) by Guardian, not taken from the repository."
echo; cat "$PATCH" | head -80; echo
SLUG="${REPO#https://github.com/}"
read -r -p "Type the repository name ($SLUG) to confirm the push: " ANSWER
[ "$ANSWER" = "$SLUG" ] || { echo "not confirmed; nothing pushed"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
git clone --quiet "$REPO" "$WORK/repo"
cd "$WORK/repo"
DEFAULT="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" != "$DEFAULT" ] || { echo "refusing to push the default branch" >&2; exit 2; }
if [ "$(git rev-parse HEAD)" != "$BASE" ]; then
  echo "NOTE: $DEFAULT moved since the scan (scanned ${BASE:0:12}, now $(git rev-parse --short=12 HEAD)); checking the patch still applies."
fi
git apply --check "$PATCH" || { echo "the patch no longer applies; re-run the scan" >&2; exit 1; }
git checkout --quiet -b "$BRANCH"
git apply "$PATCH"
git add package.json package-lock.json
git commit --quiet -m "$TITLE" -m "Prepared by Software Supply Chain Guardian; approved by $(get approved_by). Review before merging."
git push --set-upstream origin "$BRANCH"
echo; echo "Pushed. Open a pull request: $REPO/compare/$DEFAULT...$BRANCH?expand=1"
