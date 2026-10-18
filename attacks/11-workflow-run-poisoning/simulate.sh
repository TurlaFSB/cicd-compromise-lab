#!/usr/bin/env bash
# simulate.sh — demonstrate workflow_run artifact poisoning offline, then judge
# a workflow for the unsafe pattern.
#
# A live demo needs two repos and a fork PR. This models the mechanism locally:
#
#   Part 1 (MECHANISM, always runs): build a fake artifact that a fork PR could
#     have uploaded — it carries an attacker script under scripts/. A "blind"
#     privileged consumer that runs code out of the artifact executes the
#     script (POISONED); a "validating" consumer that reads only the PR number
#     and never executes anything stays SAFE.
#
#   Part 2 (VERDICT): inspect a workflow file for the three unsafe idioms a
#     workflow_run handler must avoid — checking out the triggering head,
#     executing downloaded/checked-out code, and interpolating untrusted
#     workflow_run context into a shell. Reports POISONED or SAFE and sets the
#     exit code.
#
# Usage:
#   ./simulate.sh                 # judge the vulnerable comment.yml (default)
#   ./simulate.sh <workflow.yml>  # judge a specific workflow
#
# Exit codes:
#   0 — the workflow treats upstream output as untrusted data (no poisoning)
#   1 — the workflow consumes fork-controlled output unsafely (poisonable)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="${1:-$SCRIPT_DIR/comment.yml}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WF" ] || { echo "no workflow at $WF" >&2; exit 2; }

echo -e "${BOLD}=== Part 1: artifact poisoning mechanism (concrete) ===${NC}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A fork PR's build uploads this artifact. It contains the PR number AND, since
# the vulnerable producer uploads the whole tree, the fork's own scripts.
mkdir -p "$work/artifact/scripts"
echo "42" > "$work/artifact/NR"
cat > "$work/artifact/scripts/comment.js" <<'POC'
# stand-in for attacker-planted scripts/comment.js (shell for portability)
echo "[poc] attacker-controlled artifact code executed in privileged context" >&2
: "${GH_TOKEN:=}"; : "${DEPLOY_KEY:=}"
echo "poisoned" > "$PWD/poisoned.proof"
POC

echo "fork uploaded artifact: NR=42 plus scripts/comment.js (attacker-planted)"
echo ""

# Blind consumer (vulnerable behaviour): runs code out of the artifact.
blind=$(mktemp -d)
cp -r "$work/artifact/." "$blind/"
( cd "$blind" && GH_TOKEN="dummy-token" DEPLOY_KEY="dummy-key" sh ./scripts/comment.js ) 2>/dev/null || true
if [ -f "$blind/poisoned.proof" ]; then
  echo -e "  blind consumer:      ${RED}executed artifact code → POISONED${NC} (ran with token/secrets in env)"
fi
rm -rf "$blind"

# Validating consumer (hardened behaviour): reads only the number, validates,
# never executes anything from the artifact.
valid=$(mktemp -d)
cp -r "$work/artifact/." "$valid/"
num="$(tr -dc '0-9' < "$valid/NR" | head -c 12)"
if printf '%s' "$num" | grep -qE '^[0-9]+$'; then
  echo -e "  validating consumer: ${GREEN}read PR #$num as data, executed nothing → SAFE${NC}"
fi
rm -rf "$valid"
echo ""

echo -e "${BOLD}=== Part 2: verdict for $(basename "$WF") ===${NC}"

body=$(grep -v '^[[:space:]]*#' "$WF")

# Only workflow_run handlers are in scope for this scenario.
if ! printf '%s\n' "$body" | grep -qE '^[[:space:]]*workflow_run:[[:space:]]*$' \
   && ! printf '%s\n' "$body" | grep -qE '^on:.*workflow_run'; then
  echo "not a workflow_run-triggered workflow — scenario 11 does not apply."
  echo -e "${GREEN}SAFE${NC}"
  exit 0
fi

reasons=()

# (a) checks out the triggering run's head
if printf '%s\n' "$body" | grep -qE 'ref:[[:space:]]*\$\{\{[^}]*github\.event\.workflow_run\.(head_branch|head_sha|head_repository)'; then
  reasons+=("checks out the fork's head in the privileged context")
fi

# (b) executes code from the downloaded artifact / checked-out tree
has_dl=0
if printf '%s\n' "$body" | grep -qE 'run-id:[[:space:]]*\$\{\{[^}]*github\.event\.workflow_run\.id' \
   || printf '%s\n' "$body" | grep -qE 'listWorkflowRunArtifacts|downloadArtifact|dawidd6/action-download-artifact'; then
  has_dl=1
fi
if { [ "$has_dl" -eq 1 ] || printf '%s\n' "$body" | grep -qE 'ref:[[:space:]]*\$\{\{[^}]*workflow_run'; } \
   && printf '%s\n' "$body" | grep -qE '(^|[^[:alnum:]_])(node|python3?|bash|sh)[[:space:]]+[./]|npm[[:space:]]+(ci|install|run)|(^|[[:space:]])(source|\.)[[:space:]]+[./]'; then
  reasons+=("executes code out of the downloaded/checked-out tree")
fi

# (c) untrusted workflow_run context spliced into a run: shell
# (any workflow_run field reference that is not confined to an env:/with:/if: mapping line)
if printf '%s\n' "$body" | grep -E 'echo|curl|eval|bash|sh ' | grep -qE '\$\{\{[^}]*github\.event\.workflow_run\.(head_branch|display_title|head_repository|head_commit|name)'; then
  reasons+=("interpolates untrusted workflow_run context into a shell command")
fi

if [ "${#reasons[@]}" -gt 0 ]; then
  echo -e "${RED}POISONABLE:${NC} this workflow_run handler trusts fork-controlled output."
  for r in "${reasons[@]}"; do echo "  - $r"; done
  echo "  A fork PR that poisons the upstream artifact (or its branch name) reaches"
  echo "  the base repo's token and secrets through this handler."
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} upstream output is treated as untrusted data —"
echo "       no head checkout, no artifact execution, no untrusted context in a shell."
exit 0
