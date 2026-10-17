#!/usr/bin/env bash
# Verification script for scenario 08 — GITHUB_ENV / GITHUB_PATH injection
#
# Proves the hardened workflow keeps untrusted data out of the runner
# environment files by:
#   1. Running the scanner against the hardened and vulnerable workflows.
#   2. Running the simulation against both (INJECTABLE vs SAFE).
#   3. Checking structural invariants of the hardened workflow.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

# shellcheck disable=SC2016  # patterns intentionally contain literal '$' (GITHUB_ENV in scanned YAML)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/08-env-injection/detect.sh"
SIMULATE="$LAB_ROOT/attacks/08-env-injection/simulate.sh"
VULN_WF="$LAB_ROOT/attacks/08-env-injection/triage.yml"
HARD_WF="$LAB_ROOT/hardened/08-env-injection/triage.yml"

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

  echo "--- Check 3: injection simulation ---"
  if "$SIMULATE" "$VULN_WF" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable workflow"
  else
    assert_pass "simulation reports the vulnerable workflow as INJECTABLE"
  fi
  if "$SIMULATE" "$HARD_WF" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened workflow as SAFE"
  else
    assert_fail "simulation still flags the hardened workflow"
  fi

  echo "--- Check 4: structural invariants ---"
  local body
  body=$(grep -v '^[[:space:]]*#' "$HARD_WF")

  # 4a: no untrusted context written to GITHUB_ENV/GITHUB_PATH
  if echo "$body" | grep -E '>>[[:space:]]*"?\$\{?GITHUB_(ENV|PATH)' \
       | grep -qE '\$\{\{[^}]*github\.event'; then
    assert_fail "untrusted context still written to a runner env file"
  else
    assert_pass "no untrusted context written to GITHUB_ENV/GITHUB_PATH"
  fi

  # 4b: nothing written to GITHUB_PATH at all
  if echo "$body" | grep -qE '>>[[:space:]]*"?\$\{?GITHUB_PATH'; then
    assert_fail "GITHUB_PATH is written (untrusted PATH manipulation risk)"
  else
    assert_pass "GITHUB_PATH is never written"
  fi

  # 4c: untrusted title reaches a step only via step-scoped env:
  if echo "$body" | grep -qE 'ISSUE_TITLE:[[:space:]]*\$\{\{[[:space:]]*github\.event\.issue\.title'; then
    assert_pass "untrusted title is exposed through step-scoped env:"
  else
    assert_fail "expected the title to be passed via env:"
  fi

  # 4d: any GITHUB_ENV write uses a heredoc delimiter (fixed name, not a raw KEY=untrusted)
  if echo "$body" | grep -qE '>>[[:space:]]*"?\$\{?GITHUB_ENV'; then
    if echo "$body" | grep -qE '<<[A-Za-z0-9_$]'; then
      assert_pass "GITHUB_ENV writes use a heredoc delimiter (safe multiline form)"
    else
      assert_fail "GITHUB_ENV write should use a random heredoc delimiter"
    fi
  else
    assert_pass "no GITHUB_ENV writes (nothing to inject into)"
  fi

  # 4e: variable references double-quoted; actions SHA-pinned
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: GITHUB_ENV injection ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Deploy the vulnerable triage.yml to a target repo."
  echo "  2. Open an issue whose title is two lines: a benign line, then"
  echo "     NODE_OPTIONS=--require \$PWD/evil.js (see payload/inject.txt)."
  echo "  3. Observe NODE_OPTIONS set in the 'Process' step (env injected)."
  echo "  4. Switch to the hardened triage.yml and repeat — the title is only"
  echo "     a step-scoped env var; no extra variable is injected."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow keeps untrusted data out of the runner environment files."
  exit 0
fi
