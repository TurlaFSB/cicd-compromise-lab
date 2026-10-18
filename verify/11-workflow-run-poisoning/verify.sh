#!/usr/bin/env bash
# Verification script for scenario 11 — workflow_run artifact poisoning
#
# Proves the hardened workflow_run handler treats fork-controlled upstream
# output as untrusted data by:
#   1. Running the scanner against the hardened and vulnerable consumers.
#   2. Running the simulation against both (POISONABLE vs SAFE).
#   3. Checking structural invariants of the hardened consumer.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/11-workflow-run-poisoning/detect.sh"
SIMULATE="$LAB_ROOT/attacks/11-workflow-run-poisoning/simulate.sh"
VULN_WF="$LAB_ROOT/attacks/11-workflow-run-poisoning/comment.yml"
HARD_WF="$LAB_ROOT/hardened/11-workflow-run-poisoning/comment.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

verify_static() {
  echo "=== Structural verification of hardened workflow ==="
  echo ""
  for f in "$DETECT" "$SIMULATE" "$HARD_WF" "$VULN_WF"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  echo "--- Check 1: detection scanner vs. hardened consumer ---"
  local tmp
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$HARD_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened consumer"
  else
    assert_pass "scanner reports no findings on the hardened consumer"
  fi
  rm -rf "$tmp"

  echo "--- Check 2: detection scanner vs. vulnerable consumer ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$VULN_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_pass "scanner correctly flags the vulnerable consumer"
  else
    assert_fail "scanner missed the vulnerable consumer"
  fi
  rm -rf "$tmp"

  echo "--- Check 3: poisoning simulation ---"
  if "$SIMULATE" "$VULN_WF" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable consumer"
  else
    assert_pass "simulation reports the vulnerable consumer as POISONABLE"
  fi
  if "$SIMULATE" "$HARD_WF" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened consumer as SAFE"
  else
    assert_fail "simulation still flags the hardened consumer"
  fi

  echo "--- Check 4: structural invariants ---"
  local body
  body=$(grep -v '^[[:space:]]*#' "$HARD_WF")

  # 4a: it IS a workflow_run handler (so the hardening is meaningful)
  if printf '%s\n' "$body" | grep -qE '^[[:space:]]*workflow_run:[[:space:]]*$'; then
    assert_pass "hardened workflow is still a workflow_run handler"
  else
    assert_fail "hardened workflow is no longer triggered by workflow_run"
  fi

  # 4b: never checks out the triggering head
  if printf '%s\n' "$body" | grep -qE 'ref:[[:space:]]*\$\{\{[^}]*github\.event\.workflow_run\.(head_branch|head_sha|head_repository)'; then
    assert_fail "hardened workflow still checks out the triggering head"
  else
    assert_pass "hardened workflow never checks out the triggering head"
  fi

  # 4c: never executes code from the downloaded/checked-out tree
  if printf '%s\n' "$body" | grep -qE '(^|[^[:alnum:]_])(node|python3?|bash|sh)[[:space:]]+[./]|npm[[:space:]]+(ci|install|run)|(^|[[:space:]])(source|\.)[[:space:]]+[./]'; then
    assert_fail "hardened workflow still executes code from the tree"
  else
    assert_pass "hardened workflow executes nothing from the artifact/tree"
  fi

  # 4d: no untrusted workflow_run context in a shell command
  if printf '%s\n' "$body" | grep -E 'echo|curl|eval|bash|sh ' \
       | grep -qE '\$\{\{[^}]*github\.event\.workflow_run\.(head_branch|display_title|head_repository|head_commit|name)'; then
    assert_fail "hardened workflow still splices untrusted workflow_run context into a shell"
  else
    assert_pass "no untrusted workflow_run context reaches a shell command"
  fi

  # 4e: the PR number read from the artifact is validated as an integer
  if printf '%s\n' "$body" | grep -qE "tr -dc '0-9'|=~[[:space:]]*\^\[0-9\]|grep -qE '\^\[0-9\]"; then
    assert_pass "PR number from the artifact is validated as an integer"
  else
    assert_fail "expected the artifact's PR number to be validated numerically"
  fi

  # 4f: least privilege — read-only workflow floor
  if printf '%s\n' "$body" | grep -qE '^permissions:' \
     && awk '/^permissions:/{p=1;next} p&&/^[^[:space:]]/{p=0} p&&/contents:[[:space:]]*read/{f=1} END{exit !f}' "$HARD_WF"; then
    assert_pass "workflow-level permissions floor is read-only"
  else
    assert_fail "expected a read-only workflow-level permissions floor"
  fi

  # 4g: actions pinned by commit SHA
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: workflow_run artifact poisoning ==="
  echo ""
  echo "MANUAL STEPS REQUIRED (two repos, one fork):"
  echo "  1. Deploy attacks/11 build.yml + comment.yml to a target repo."
  echo "  2. From a fork, open a PR that adds scripts/comment.js (see"
  echo "     payload/comment.js) and lets the build upload the full tree."
  echo "  3. When 'PR comment' runs, observe poisoned.proof.json — attacker"
  echo "     code ran in the base repo context with the write token in env."
  echo "  4. Switch to hardened build.yml + comment.yml and repeat: the"
  echo "     consumer downloads only pr-number, validates it, and executes"
  echo "     nothing from the fork."
  echo ""
}

case "${1:-}" in
  static) verify_static ;;
  live)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      echo "usage: $0 live <owner/repo> <target-clone-path>" >&2
      exit 2
    fi
    verify_live "$2" "$3"
    ;;
  *) verify_static ;;
esac

echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}VERIFICATION FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow_run handler treats fork output as untrusted data."
  exit 0
fi
