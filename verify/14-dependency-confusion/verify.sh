#!/usr/bin/env bash
# Verification script for scenario 14 — dependency confusion / install-script abuse
#
# Proves the hardened install phase resists both attacks by:
#   1. Running the scanner against the hardened and vulnerable configs.
#   2. Running the mechanism simulation against both directories.
#   3. Checking structural invariants of the hardened workflow and .npmrc.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/14-dependency-confusion/detect.sh"
SIMULATE="$LAB_ROOT/attacks/14-dependency-confusion/simulate.sh"
VULN_DIR="$LAB_ROOT/attacks/14-dependency-confusion"
HARD_DIR="$LAB_ROOT/hardened/14-dependency-confusion"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

stage() {  # stage <dir> into a fresh repo-shaped tree, echo the tree root
  local src="$1" d
  d=$(mktemp -d); mkdir -p "$d/.github/workflows"
  cp "$src/ci.yml" "$d/.github/workflows/"
  cp "$src/package.json" "$d/"
  cp "$src/.npmrc" "$d/"
  echo "$d"
}

verify_static() {
  echo "=== Structural verification of hardened install phase ==="
  echo ""
  for f in "$DETECT" "$SIMULATE" "$VULN_DIR/ci.yml" "$HARD_DIR/ci.yml" "$HARD_DIR/.npmrc"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  local d out
  echo "--- Check 1: scanner vs. hardened config ---"
  d=$(stage "$HARD_DIR")
  if ("$DETECT" static "$d" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened config"
  else
    assert_pass "scanner reports no findings on the hardened config"
  fi
  rm -rf "$d"

  echo "--- Check 2: scanner vs. vulnerable config ---"
  d=$(stage "$VULN_DIR")
  out=$("$DETECT" static "$d" 2>/dev/null || true)
  if grep -q "FINDING" <<<"$out"; then
    assert_pass "scanner flags the vulnerable config"
  else
    assert_fail "scanner missed the vulnerable config"
  fi
  for v in "PIPE TO SHELL" "NO LOCKFILE INSTALL" "INSTALL SCRIPTS ENABLED" "UNPINNED SCOPE"; do
    if grep -q "$v" <<<"$out"; then
      assert_pass "vector fires: $v"
    else
      assert_fail "vector missing: $v"
    fi
  done
  rm -rf "$d"

  echo "--- Check 3: mechanism simulation ---"
  if "$SIMULATE" "$VULN_DIR" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable config"
  else
    assert_pass "simulation reports the vulnerable config as VULNERABLE"
  fi
  if "$SIMULATE" "$HARD_DIR" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened config as SAFE"
  else
    assert_fail "simulation still flags the hardened config"
  fi

  echo "--- Check 4: structural invariants ---"
  local ci="$HARD_DIR/ci.yml" npmrc="$HARD_DIR/.npmrc" body
  body=$(grep -vE '^[[:space:]]*#' "$ci")

  # 4a: npm ci (lockfile install), not npm install
  if printf '%s\n' "$body" | grep -qE 'npm[[:space:]]+ci([[:space:]]|$)' \
     && ! printf '%s\n' "$body" | grep -qE 'npm[[:space:]]+(install|i)([[:space:]]|$)'; then
    assert_pass "hardened workflow uses 'npm ci' (locked install)"
  else
    assert_fail "hardened workflow should use 'npm ci', not 'npm install'"
  fi

  # 4b: --ignore-scripts on the install
  if printf '%s\n' "$body" | grep -qE -- '--ignore-scripts'; then
    assert_pass "install uses --ignore-scripts"
  else
    assert_fail "install should use --ignore-scripts"
  fi

  # 4c: no pipe-to-shell
  if printf '%s\n' "$body" | grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash)([[:space:]]|$)'; then
    assert_fail "a remote script is still piped into a shell"
  else
    assert_pass "no remote script is piped into a shell"
  fi

  # 4d: remote fetch is checksum-verified
  if printf '%s\n' "$body" | grep -qE 'sha256sum[[:space:]]+(-c|--check)'; then
    assert_pass "the fetched bootstrap script is checksum-verified"
  else
    assert_fail "expected a checksum check on the fetched script"
  fi

  # 4e: internal scope pinned, scripts disabled in .npmrc
  if grep -qE '^@turla-lab:registry=' "$npmrc"; then
    assert_pass ".npmrc pins the @turla-lab scope to a registry"
  else
    assert_fail ".npmrc should pin the @turla-lab scope"
  fi
  if grep -qE '^ignore-scripts=true' "$npmrc"; then
    assert_pass ".npmrc disables lifecycle scripts (ignore-scripts=true)"
  else
    assert_fail ".npmrc should set ignore-scripts=true"
  fi

  # 4f: actions SHA-pinned
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$ci" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$ci" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: dependency confusion / install-script abuse ==="
  echo ""
  echo "MANUAL STEPS REQUIRED (needs a private registry and dummy packages):"
  echo "  1. Publish @turla-lab/internal-utils@1.2.0 to the internal registry."
  echo "  2. With the vulnerable .npmrc (scope unpinned), run the vulnerable"
  echo "     ci.yml; npm resolves the scope against the public registry."
  echo "  3. Switch to the hardened .npmrc (scope pinned) + 'npm ci"
  echo "     --ignore-scripts'; the package can only come from the internal"
  echo "     registry and no lifecycle scripts run."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened install phase resists dependency confusion and install-script abuse."
  exit 0
fi
