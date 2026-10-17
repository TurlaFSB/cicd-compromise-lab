#!/usr/bin/env bash
# simulate.sh — show how a persistent (reused) self-hosted runner carries an
# implant from one job to the next, and judge a workflow for the exposure.
#
# Two parts:
#   1. MECHANISM (always runs): drop a benign implant (payload/persist.sh) in
#      a runner "home" directory, then simulate the NEXT job two ways —
#      a reused runner (same home: implant still there) and an ephemeral
#      runner (fresh home: implant gone). This proves ephemerality is what
#      defeats persistence, independent of any workflow.
#   2. VERDICT: inspect a workflow — does a job triggered by untrusted events
#      (pull_request / pull_request_target) run on a self-hosted runner?
#      If so the runner executes attacker-controlled code and, if reused,
#      carries an implant into later jobs. Reports PERSISTS or SAFE.
#
# Usage:
#   ./simulate.sh                 # judge the vulnerable ci.yml (default)
#   ./simulate.sh <workflow.yml>  # judge a specific workflow
#
# Exit codes:
#   0 — untrusted code does not run on a self-hosted runner (no exposure)
#   1 — untrusted code runs on a self-hosted runner (persistence exposure)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="${1:-$SCRIPT_DIR/ci.yml}"
PERSIST="$SCRIPT_DIR/payload/persist.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WF" ] || { echo "no workflow at $WF" >&2; exit 2; }

echo -e "${BOLD}=== Part 1: persistence mechanism (concrete) ===${NC}"
base=$(mktemp -d)
trap 'rm -rf "$base"' EXIT

# Job 1 runs untrusted code and drops an implant in the runner's home.
runner_home="$base/runner-home"
bash "$PERSIST" "$runner_home" >/dev/null
echo "job 1 (untrusted PR code) dropped an implant in the runner home"

# Job 2 on a REUSED runner: same home directory.
if [ -f "$runner_home/.lab-implant" ]; then
  echo -e "  reused runner:    ${RED}implant still present → runs in job 2${NC}"
fi
# Job 2 on an EPHEMERAL runner: a brand-new home directory.
fresh_home="$base/fresh-home"; mkdir -p "$fresh_home"
if [ -f "$fresh_home/.lab-implant" ]; then
  echo "  ephemeral runner: implant present (unexpected)"
else
  echo -e "  ephemeral runner: ${GREEN}fresh machine → implant gone${NC}"
fi
echo ""

echo -e "${BOLD}=== Part 2: verdict for $(basename "$WF") ===${NC}"

# Untrusted triggers in the workflow's on: block.
untrusted=0
if awk '/^on:/{f=1;next} f&&/^[^[:space:]#]/{f=0} f{print}' "$WF" \
   | grep -qE '(^|[[:space:],])(pull_request|pull_request_target)([[:space:],:]|$)'; then
  untrusted=1
fi

# Any job on a self-hosted runner. GitHub-hosted labels start with
# ubuntu-/windows-/macos-; everything else on a runs-on is self-hosted.
self_hosted=0
if grep -qE '^[[:space:]]*runs-on:.*self-hosted' "$WF"; then
  self_hosted=1
elif grep -qE '^[[:space:]]*runs-on:' "$WF" \
     && ! grep -qE '^[[:space:]]*runs-on:[[:space:]]*\[?[[:space:]]*["'"'"']?(ubuntu|windows|macos)-' "$WF"; then
  # runs-on present but not a known hosted label → treat as self-hosted/custom
  self_hosted=1
fi

echo "untrusted trigger (pull_request*):      $([ $untrusted -eq 1 ] && echo yes || echo no)"
echo "a job runs on a self-hosted runner:     $([ $self_hosted -eq 1 ] && echo yes || echo no)"
echo ""

if [ "$untrusted" -eq 1 ] && [ "$self_hosted" -eq 1 ]; then
  echo -e "${RED}PERSISTS:${NC} untrusted PR code runs on a self-hosted runner."
  echo "  On a reused runner an implant survives into later jobs. Run untrusted"
  echo "  code on ephemeral GitHub-hosted runners, or on single-use self-hosted"
  echo "  runners (--ephemeral), never on a shared persistent one."
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} untrusted code does not run on a persistent self-hosted runner."
exit 0
