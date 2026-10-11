#!/usr/bin/env bash
# Verification script for scenario 05 — cache poisoning
#
# Proves the hardened workflows close the poisoning path by:
#   1. Running the detection scanner against the vulnerable and the hardened
#      workflow pair — vulnerable triggers findings, hardened does not.
#   2. Running the cache-scoping simulation against both pairs — it reports
#      POISONED for the vulnerable pair and SAFE for the hardened pair.
#   3. Checking structural invariants of the hardened workflows.
#
# Usage:
#   ./verify.sh static              # offline structural checks (default)
#   ./verify.sh live <repo> <clone> # manual live-verification guidance
#
# Exit codes:
#   0 — verification passed
#   1 — verification FAILED
#   2 — usage error or missing dependency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/05-cache-poisoning/detect.sh"
SIMULATE="$LAB_ROOT/attacks/05-cache-poisoning/simulate.sh"
VULN_PR="$LAB_ROOT/attacks/05-cache-poisoning/pr-check.yml"
VULN_REL="$LAB_ROOT/attacks/05-cache-poisoning/release.yml"
HARD_PR="$LAB_ROOT/hardened/05-cache-poisoning/pr-check.yml"
HARD_REL="$LAB_ROOT/hardened/05-cache-poisoning/release.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

verify_static() {
  echo "=== Structural verification of hardened workflows ==="
  echo ""

  for f in "$DETECT" "$SIMULATE" "$HARD_PR" "$HARD_REL"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  # --- Check 1: scanner clears the hardened pair ---
  echo "--- Check 1: detection scanner vs. hardened workflows ---"
  local tmp
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$HARD_PR" "$HARD_REL" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened workflows"
  else
    assert_pass "scanner reports no findings on the hardened workflows"
  fi
  rm -rf "$tmp"

  # --- Check 2: scanner flags the vulnerable pair ---
  echo "--- Check 2: detection scanner vs. vulnerable workflows ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$VULN_PR" "$VULN_REL" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_pass "scanner correctly flags the vulnerable workflows"
  else
    assert_fail "scanner missed the vulnerable workflows"
  fi
  rm -rf "$tmp"

  # --- Check 3: simulation POISONED on vulnerable, SAFE on hardened ---
  echo "--- Check 3: cache-scoping simulation ---"
  if "$SIMULATE" "$VULN_PR" "$VULN_REL" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable pair as poisoned"
  else
    assert_pass "simulation reports the vulnerable pair as POISONED"
  fi
  if "$SIMULATE" "$HARD_PR" "$HARD_REL" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened pair as SAFE"
  else
    assert_fail "simulation still reports the hardened pair as poisoned"
  fi

  # --- Check 4: structural invariants ---
  echo "--- Check 4: structural invariants ---"

  # 4a: the writer (PR) workflow must be read-only cache (no read-write save)
  if grep -qE 'uses:[[:space:]]*actions/cache/restore@' "$HARD_PR" \
     && ! grep -qE 'uses:[[:space:]]*actions/cache@' "$HARD_PR"; then
    assert_pass "PR workflow uses read-only actions/cache/restore (cannot write a cache)"
  else
    assert_fail "PR workflow should use actions/cache/restore, not read-write actions/cache"
  fi

  # 4b: every cache key in both hardened files is bound to hashFiles()
  local bad_keys
  bad_keys=$(awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && /^[[:space:]]*key:[[:space:]]*[^[:space:]]/ {
      if ($0 !~ /hashFiles\(/) print; in_cache = 0
    }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0 }
  ' "$HARD_PR" "$HARD_REL" || true)
  if [ -z "$bad_keys" ]; then
    assert_pass "all cache keys are bound to hashFiles() (not forgeable by a fork PR)"
  else
    assert_fail "a cache key is not bound to hashFiles(): $bad_keys"
  fi

  # 4c: no restore-keys in either hardened file (no fuzzy prefix matching)
  if grep -qE '^[[:space:]]*restore-keys:' "$HARD_PR" "$HARD_REL"; then
    assert_fail "restore-keys present — fuzzy prefix matching reintroduces the risk"
  else
    assert_pass "no restore-keys (only exact, content-bound keys match)"
  fi

  # 4d: no executable/output directories cached in either file
  local exec_paths
  exec_paths=$(awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && /^[[:space:]]*path:/ { in_path = 1; next }
    in_path && /^[[:space:]]+[^[:space:]#]/ { line = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line); print line; next }
    in_path && /^[[:space:]]*[a-z_-]+:/ { in_path = 0 }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0; in_path = 0 }
  ' "$HARD_PR" "$HARD_REL" | grep -E '(^|/)(dist|build|out|bin|\.bin|\.venv|target|node_modules)(/|$)' || true)
  if [ -z "$exec_paths" ]; then
    assert_pass "only download directories cached (no build output / binaries)"
  else
    assert_fail "executable/output paths still cached: $exec_paths"
  fi

  # 4e: the release workflow always rebuilds (unconditional npm ci + build)
  if grep -qE '^[[:space:]]*-[[:space:]]*run:[[:space:]]*npm ci' "$HARD_REL" \
     && grep -qE 'npm run build' "$HARD_REL" \
     && ! grep -qE 'if \[ ! -d (node_modules|dist) \]' "$HARD_REL"; then
    assert_pass "release workflow always builds from source (cache cannot substitute)"
  else
    assert_fail "release workflow should run npm ci + build unconditionally"
  fi

  # 4f: release job keeps least-privilege, per-job permissions + environment
  if grep -qE '^[[:space:]]+permissions:' "$HARD_REL" \
     && ! grep -qE '^permissions:' "$HARD_REL"; then
    assert_pass "release workflow declares per-job permissions (not workflow-level)"
  else
    assert_fail "release workflow should declare permissions per job"
  fi
  if grep -qE '^[[:space:]]+environment:' "$HARD_REL"; then
    assert_pass "release job uses environment: protection"
  else
    assert_fail "release job should use environment: protection"
  fi

  # 4g: actions are SHA-pinned in both hardened files
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_PR" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_PR" "$HARD_REL" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA in both hardened workflows"
  else
    assert_fail "actions should be pinned by commit SHA, not mutable tags"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: cache poisoning ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Deploy the vulnerable pr-check.yml and release.yml to a target repo."
  echo "  2. From a fork, open a PR whose build step writes"
  echo "     attacks/05-cache-poisoning/payload/poison.js into dist/ before the"
  echo "     cache is saved under 'build-cache'."
  echo "  3. Merge or push to main; release.yml restores the poisoned cache and"
  echo "     the .poison-marker proves the restored content was executed."
  echo "  4. Replace both with the hardened workflows and repeat — the fork PR"
  echo "     can no longer write a key the release build restores, and the"
  echo "     release always rebuilds from source."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflows close the cache poisoning path."
  exit 0
fi
