#!/usr/bin/env bash
# Verification script for scenario 07 — self-hosted runner persistence
#
# Proves the hardened workflow removes the persistence exposure by:
#   1. Running the scanner against the hardened and vulnerable workflows.
#   2. Running the simulation against both (PERSISTS vs SAFE).
#   3. Checking structural invariants of the hardened workflow.
#
# Usage:
#   ./verify.sh static              # offline structural checks (default)
#   ./verify.sh live <repo> <clone> # manual live-verification guidance
#
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/07-runner-persistence/detect.sh"
SIMULATE="$LAB_ROOT/attacks/07-runner-persistence/simulate.sh"
VULN_WF="$LAB_ROOT/attacks/07-runner-persistence/ci.yml"
HARD_WF="$LAB_ROOT/hardened/07-runner-persistence/ci.yml"

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

  echo "--- Check 1: detection scanner vs. hardened workflow ---"
  local tmp
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$HARD_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened workflow"
  else
    assert_pass "scanner reports no findings on the hardened workflow"
  fi
  rm -rf "$tmp"

  echo "--- Check 2: detection scanner vs. vulnerable workflow ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$VULN_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_pass "scanner correctly flags the vulnerable workflow"
  else
    assert_fail "scanner missed the vulnerable workflow"
  fi
  rm -rf "$tmp"

  echo "--- Check 3: persistence simulation ---"
  if "$SIMULATE" "$VULN_WF" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable workflow"
  else
    assert_pass "simulation reports the vulnerable workflow as PERSISTS"
  fi
  if "$SIMULATE" "$HARD_WF" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened workflow as SAFE"
  else
    assert_fail "simulation still flags the hardened workflow"
  fi

  echo "--- Check 4: structural invariants ---"

  # 4a: untrusted-trigger job runs on a GitHub-hosted runner
  if grep -qE '^[[:space:]]*runs-on:[[:space:]]*(ubuntu|windows|macos)-' "$HARD_WF"; then
    assert_pass "job runs on a GitHub-hosted (ephemeral) runner"
  else
    assert_fail "untrusted-trigger job should run on a GitHub-hosted runner"
  fi

  # 4b: no self-hosted runner anywhere
  if grep -qE '^[[:space:]]*runs-on:.*self-hosted' "$HARD_WF"; then
    assert_fail "self-hosted runner still present"
  else
    assert_pass "no self-hosted runner used"
  fi

  # 4c: no persistence-writing steps
  if grep -qE '(crontab|/etc/cron|systemctl --user|~/\.bashrc|~/\.profile|/etc/profile\.d|autostart)' "$HARD_WF"; then
    assert_fail "a persistence-writing step is present"
  else
    assert_pass "no persistence-writing steps"
  fi

  # 4d: least-privilege permissions and SHA-pinned actions
  if grep -qE '^permissions:' "$HARD_WF" && grep -qE 'contents:[[:space:]]*read' "$HARD_WF"; then
    assert_pass "read-only permissions declared"
  else
    assert_fail "expected read-only permissions"
  fi
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: runner persistence ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Register a self-hosted runner and deploy the vulnerable ci.yml."
  echo "  2. From a fork, open a PR whose test step runs payload/persist.sh"
  echo "     against a persistent dir (e.g. \$HOME). Observe the implant."
  echo "  3. Trigger a second job on the same runner — the implant is still there."
  echo "  4. Switch to the hardened ci.yml (GitHub-hosted) or re-register the"
  echo "     self-hosted runner with --ephemeral; the implant no longer survives."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow removes the runner persistence exposure."
  exit 0
fi
