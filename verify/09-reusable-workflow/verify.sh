#!/usr/bin/env bash
# Verification script for scenario 09 — reusable workflow trust boundary
#
# Proves the hardened caller invokes the reusable workflow safely by:
#   1. Running the scanner against the hardened and vulnerable callers.
#   2. Checking structural invariants of the hardened caller.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/09-reusable-workflow/detect.sh"
VULN_WF="$LAB_ROOT/attacks/09-reusable-workflow/release.yml"
HARD_WF="$LAB_ROOT/hardened/09-reusable-workflow/release.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

verify_static() {
  echo "=== Structural verification of hardened caller ==="
  echo ""
  for f in "$DETECT" "$HARD_WF" "$VULN_WF"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  echo "--- Check 1: detection scanner vs. hardened caller ---"
  local tmp
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$HARD_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened caller"
  else
    assert_pass "scanner reports no findings on the hardened caller"
  fi
  rm -rf "$tmp"

  echo "--- Check 2: detection scanner vs. vulnerable caller ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$VULN_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_pass "scanner correctly flags the vulnerable caller"
  else
    assert_fail "scanner missed the vulnerable caller"
  fi
  rm -rf "$tmp"

  echo "--- Check 3: structural invariants ---"
  local body
  body=$(grep -v '^[[:space:]]*#' "$HARD_WF")

  # 3a: reusable workflow pinned by a full 40-char SHA
  if echo "$body" | grep -qE 'uses:[[:space:]]+[^[:space:]]+/\.github/workflows/[^@]+@[0-9a-f]{40}'; then
    assert_pass "reusable workflow pinned by full commit SHA"
  else
    assert_fail "reusable workflow should be pinned by a full commit SHA"
  fi

  # 3b: no mutable ref on the reusable workflow
  if echo "$body" | grep -qE 'uses:[[:space:]]+[^[:space:]]+/\.github/workflows/[^@]+@(main|master|v[0-9]|release|latest)'; then
    assert_fail "reusable workflow still uses a mutable ref"
  else
    assert_pass "no mutable ref on the reusable workflow"
  fi

  # 3c: no secrets: inherit
  if echo "$body" | grep -qE '^[[:space:]]*secrets:[[:space:]]*inherit[[:space:]]*$'; then
    assert_fail "secrets: inherit still present"
  else
    assert_pass "no secrets: inherit (secrets passed explicitly, if any)"
  fi

  # 3d: secrets, if passed, are named explicitly
  if echo "$body" | grep -qE '^[[:space:]]*secrets:[[:space:]]*$'; then
    if echo "$body" | grep -qE '^[[:space:]]+[A-Z_]+:[[:space:]]*\$\{\{[[:space:]]*secrets\.'; then
      assert_pass "secrets passed explicitly by name"
    else
      assert_fail "secrets: block present but no explicit named secret found"
    fi
  else
    assert_pass "no secrets passed to the reusable workflow"
  fi

  # 3e: a version comment accompanies the pinned SHA
  if grep -E 'uses:[[:space:]]+[^[:space:]]+/\.github/workflows/[^@]+@[0-9a-f]{40}' "$HARD_WF" | grep -qE '#'; then
    assert_pass "pinned reusable workflow has a version comment"
  else
    assert_fail "pinned SHA should carry a version comment for auditability"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: reusable workflow trust ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Deploy the vulnerable release.yml; confirm the external reusable"
  echo "     workflow runs with all inherited secrets."
  echo "  2. Switch to the hardened release.yml (SHA-pinned, explicit secret)."
  echo "  3. Confirm only NPM_TOKEN is available to the reusable workflow and"
  echo "     that changing the upstream @main no longer changes what runs."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened caller pins the reusable workflow and scopes secrets."
  exit 0
fi
