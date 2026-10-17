#!/usr/bin/env bash
# Verification script for scenario 10 — GITHUB_TOKEN over-privilege
#
# Proves the hardened workflows scope the token by:
#   1. Running the scanner against the hardened and vulnerable workflow sets.
#   2. Confirming each detection vector fires on a purpose-built fixture.
#   3. Running the privilege simulation against both sets.
#   4. Checking structural invariants of the hardened workflows.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/10-token-overprivilege/detect.sh"
SIM="$LAB_ROOT/attacks/10-token-overprivilege/simulate.sh"
VULN_DIR="$LAB_ROOT/attacks/10-token-overprivilege"
HARD_DIR="$LAB_ROOT/hardened/10-token-overprivilege"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

# scan_set <dir-of-yml> -> prints scanner output (never fails the script)
scan_set() {
  local src="$1" tmp out
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$src"/*.yml "$tmp/.github/workflows/"
  out=$("$DETECT" static "$tmp" 2>/dev/null || true)
  rm -rf "$tmp"
  printf '%s\n' "$out"
}

# scan_text <yaml-text> -> prints scanner output for a one-off fixture
scan_text() {
  local tmp out
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  printf '%s\n' "$1" > "$tmp/.github/workflows/fixture.yml"
  out=$("$DETECT" static "$tmp" 2>/dev/null || true)
  rm -rf "$tmp"
  printf '%s\n' "$out"
}

verify_static() {
  echo "=== Structural verification of hardened workflows ==="
  echo ""
  local f
  for f in "$DETECT" "$SIM" "$HARD_DIR/ci.yml" "$VULN_DIR/ci.yml"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  local out
  echo "--- Check 1: scanner vs. hardened workflows ---"
  out=$(scan_set "$HARD_DIR")
  if grep -q "FINDING" <<< "$out"; then
    assert_fail "scanner flagged the hardened workflows"
  else
    assert_pass "scanner reports no findings on the hardened workflows"
  fi

  echo "--- Check 2: scanner vs. vulnerable workflows ---"
  out=$(scan_set "$VULN_DIR")
  if grep -q "FINDING" <<< "$out"; then
    assert_pass "scanner flags the vulnerable workflows"
  else
    assert_fail "scanner missed the vulnerable workflows"
  fi

  echo "--- Check 3: each detection vector fires ---"
  if grep -q "WRITE-ALL" <<< "$out"; then
    assert_pass "vector WRITE-ALL detected"
  else
    assert_fail "vector WRITE-ALL not detected"
  fi
  if grep -q "NO PERMISSIONS BLOCK" <<< "$out"; then
    assert_pass "vector NO PERMISSIONS BLOCK detected"
  else
    assert_fail "vector NO PERMISSIONS BLOCK not detected"
  fi
  if grep -q "WRITE ON UNTRUSTED TRIGGER" <<< "$out"; then
    assert_pass "vector WRITE ON UNTRUSTED TRIGGER detected"
  else
    assert_fail "vector WRITE ON UNTRUSTED TRIGGER not detected"
  fi
  local fixture
  fixture=$'name: x\non: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n'
  if grep -q "WORKFLOW-LEVEL WRITE" <<< "$(scan_text "$fixture")"; then
    assert_pass "vector WORKFLOW-LEVEL WRITE detected (fixture)"
  else
    assert_fail "vector WORKFLOW-LEVEL WRITE not detected"
  fi

  echo "--- Check 4: low-risk and read-only grants are not flagged ---"
  fixture=$'name: x\non: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      pull-requests: write\n    steps:\n      - run: echo hi\n'
  if grep -q "FINDING" <<< "$(scan_text "$fixture")"; then
    assert_fail "pull-requests: write on an untrusted trigger was over-flagged"
  else
    assert_pass "low-risk write (pull-requests) on an untrusted trigger is not flagged"
  fi

  echo "--- Check 5: privilege simulation ---"
  if "$SIM" >/dev/null 2>&1; then
    assert_fail "simulation reported the vulnerable workflows as scoped"
  else
    assert_pass "simulation reports the vulnerable workflows OVER-PRIVILEGED"
  fi
  if "$SIM" "$HARD_DIR"/*.yml >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened workflows scoped"
  else
    assert_fail "simulation reported the hardened workflows over-privileged"
  fi

  echo "--- Check 6: structural invariants ---"
  local wf body missing_floor="" has_write_all="" untrusted_ci="" unpinned=""
  for wf in "$HARD_DIR"/*.yml; do
    body=$(grep -v '^[[:space:]]*#' "$wf")
    if ! grep -qE '^permissions:' <<< "$body"; then missing_floor="$missing_floor $(basename "$wf")"; fi
    if grep -qE 'permissions:[[:space:]]*write-all' <<< "$body"; then has_write_all="$has_write_all $(basename "$wf")"; fi
    if grep -E '^[[:space:]]+-?[[:space:]]*uses:' <<< "$body" | grep -vE 'uses:[[:space:]]+\./' | grep -qvE '@[0-9a-f]{40}'; then
      unpinned="$unpinned $(basename "$wf")"
    fi
  done
  if grep -qE 'pull_request_target' <<< "$(grep -v '^[[:space:]]*#' "$HARD_DIR/ci.yml")"; then
    untrusted_ci="ci.yml"
  fi

  if [ -z "$missing_floor" ]; then
    assert_pass "every hardened workflow declares a workflow-level permissions floor"
  else
    assert_fail "no workflow-level permissions block in:$missing_floor"
  fi
  if [ -z "$has_write_all" ]; then
    assert_pass "no hardened workflow uses write-all"
  else
    assert_fail "write-all present in:$has_write_all"
  fi
  if [ -z "$untrusted_ci" ]; then
    assert_pass "hardened CI does not run on pull_request_target"
  else
    assert_fail "hardened CI still triggers on pull_request_target"
  fi
  if [ -z "$unpinned" ]; then
    assert_pass "all actions in hardened workflows are pinned by full commit SHA"
  else
    assert_fail "unpinned actions in:$unpinned"
  fi
  if grep -v '^[[:space:]]*#' "$HARD_DIR/ci.yml" | grep -qE 'contents:[[:space:]]*read'; then
    assert_pass "hardened CI floor is 'contents: read'"
  else
    assert_fail "hardened CI should set 'contents: read'"
  fi
  if grep -v '^[[:space:]]*#' "$HARD_DIR/release.yml" | awk '/^permissions:/{wf=1;next} /^[^ ]/{wf=0} wf&&/write/{bad=1} END{exit !bad}'; then
    assert_fail "release.yml grants write at workflow level"
  else
    assert_pass "release.yml keeps write scopes on the job, not the workflow"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: GITHUB_TOKEN scope ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Run the vulnerable ci.yml and add a step that calls"
  echo "     'gh api repos/\$GITHUB_REPOSITORY -q .permissions' and an authenticated"
  echo "     write (e.g. creating a lightweight tag); confirm both succeed."
  echo "  2. Switch to the hardened ci.yml (contents: read floor)."
  echo "  3. Repeat the write; confirm GitHub returns 403 'Resource not accessible"
  echo "     by integration'."
  echo "  4. Under Settings > Actions > General, set the default workflow permissions"
  echo "     to 'Read repository contents and packages permissions'."
  echo ""
}

case "${1:-}" in
  static) verify_static ;;
  live)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      echo "usage: $0 live <owner/repo> <target-clone-path>" >&2
      exit 2
    fi
    verify_live
    ;;
  *) verify_static ;;
esac

echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}VERIFICATION FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflows scope the GITHUB_TOKEN to what each job needs."
  exit 0
fi
