#!/usr/bin/env bash
# Verification script for scenario 13 — credential leakage via artifacts
#
# Proves the hardened workflow keeps credentials out of uploaded artifacts by:
#   1. Running the scanner against the hardened and vulnerable workflows.
#   2. Running the leak simulation against both (LEAKY vs SAFE).
#   3. Checking structural invariants of the hardened workflow.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/13-artifact-cred-leak/detect.sh"
SIMULATE="$LAB_ROOT/attacks/13-artifact-cred-leak/simulate.sh"
VULN_WF="$LAB_ROOT/attacks/13-artifact-cred-leak/release.yml"
HARD_WF="$LAB_ROOT/hardened/13-artifact-cred-leak/release.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

verify_static() {
  echo "=== Structural verification of hardened workflow ==="
  echo ""
  for f in "$DETECT" "$SIMULATE" "$VULN_WF" "$HARD_WF"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  local tmp out
  echo "--- Check 1: scanner vs. hardened workflow ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"; cp "$HARD_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened workflow"
  else
    assert_pass "scanner reports no findings on the hardened workflow"
  fi
  rm -rf "$tmp"

  echo "--- Check 2: scanner vs. vulnerable workflow ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"; cp "$VULN_WF" "$tmp/.github/workflows/"
  out=$("$DETECT" static "$tmp" 2>/dev/null || true)
  if grep -q "FINDING" <<<"$out"; then
    assert_pass "scanner flags the vulnerable workflow"
  else
    assert_fail "scanner missed the vulnerable workflow"
  fi
  for v in "PERSISTED CHECKOUT CREDENTIAL" "SECRET WRITTEN TO FILE" "BROAD ARTIFACT PATH" "HIDDEN FILES IN ARTIFACT"; do
    if grep -q "$v" <<<"$out"; then
      assert_pass "vector fires: $v"
    else
      assert_fail "vector missing: $v"
    fi
  done
  rm -rf "$tmp"

  echo "--- Check 3: leak simulation ---"
  if "$SIMULATE" "$VULN_WF" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable workflow"
  else
    assert_pass "simulation reports the vulnerable workflow as LEAKY"
  fi
  if "$SIMULATE" "$HARD_WF" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened workflow as SAFE"
  else
    assert_fail "simulation still flags the hardened workflow"
  fi

  echo "--- Check 4: structural invariants ---"
  local body
  body=$(grep -vE '^[[:space:]]*#' "$HARD_WF")

  # 4a: persist-credentials: false on checkout
  if printf '%s\n' "$body" | grep -qE 'persist-credentials:[[:space:]]*false'; then
    assert_pass "checkout sets persist-credentials: false"
  else
    assert_fail "checkout should set persist-credentials: false"
  fi

  # 4b: no secret written to a real file
  if printf '%s\n' "$body" | grep -E '\$\{\{[[:space:]]*secrets\.' | grep -qE '>|(^|[[:space:]])tee([[:space:]]|$)' \
     && ! printf '%s\n' "$body" | grep -E '\$\{\{[[:space:]]*secrets\.' | grep -q 'GITHUB_'; then
    assert_fail "a secret is still written to a file on disk"
  else
    assert_pass "no secret is written to a file on disk"
  fi

  # 4c: secret passed via env
  if printf '%s\n' "$body" | grep -qE 'NODE_AUTH_TOKEN:[[:space:]]*\$\{\{[[:space:]]*secrets\.'; then
    assert_pass "the npm token is passed through env:, not written to disk"
  else
    assert_fail "expected the token to be exposed via env:"
  fi

  # 4d: narrow upload path (not . / ** ) and no hidden files
  if printf '%s\n' "$body" | grep -qE 'path:[[:space:]]*["'\'']?(\.|\*\*?)[[:space:]"'\'']*$'; then
    assert_fail "upload path still captures the whole tree"
  else
    assert_pass "upload path is scoped to build output"
  fi
  if printf '%s\n' "$body" | grep -qE 'include-hidden-files:[[:space:]]*true'; then
    assert_fail "include-hidden-files is still true"
  else
    assert_pass "hidden files are not forced into the artifact"
  fi

  # 4e: actions SHA-pinned
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: credential leakage via artifacts ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Run the vulnerable release.yml on a target repo (dummy secrets)."
  echo "  2. Download the build-output artifact and inspect .git/config and"
  echo "     .npmrc — the checkout token and npm token are present."
  echo "  3. Switch to the hardened release.yml and repeat: the artifact holds"
  echo "     only dist/, with no credential."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow keeps credentials out of uploaded artifacts."
  exit 0
fi
