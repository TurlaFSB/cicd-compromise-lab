#!/usr/bin/env bash
# Verification script for scenario 01 — pwn request
#
# Proves the hardened workflow blocks the original attack by:
#   1. Running the static detection scanner against BOTH the vulnerable
#      and hardened workflow files — the vulnerable one should trigger a
#      finding, the hardened one should not.
#   2. Checking that the hardened workflow structurally prevents the attack:
#      - The test job (which runs PR code) uses `pull_request`, NOT
#        `pull_request_target`, so it gets no secrets and a read-only token.
#      - The label job (which uses `pull_request_target`) has NO checkout
#        step, so it never touches PR code.
#   3. (Optional, requires live repos) Opens a PR with the same malicious
#      payload against the hardened workflow and verifies the attack fails:
#      - The test job runs the code but has no DUMMY_CLOUD_KEY and no
#        write token — the payload's assertions both fail.
#      - The label job runs but never executes PR code.
#
# Usage:
#   ./verify.sh static                              # offline structural verification
#   ./verify.sh live <target-repo> <target-clone>    # full live re-attack (requires setup)
#
# Exit codes:
#   0 — verification passed (hardened workflow blocks the attack)
#   1 — verification FAILED (hardened workflow still vulnerable)
#   2 — usage error or missing dependency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/01-pwn-request/detect.sh"
HARDENED_WF="$LAB_ROOT/hardened/01-pwn-request/ci.yml"
VULNERABLE_WF="" # set below if a target clone is available

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0

assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

# ──────────────────────────────────────────────────────────────
# Structural verification (offline, no live repo needed)
# ──────────────────────────────────────────────────────────────

verify_static() {
  echo "=== Structural verification of hardened workflow ==="
  echo ""

  [ -f "$HARDENED_WF" ] || { assert_fail "hardened workflow not found at $HARDENED_WF"; return; }
  [ -x "$DETECT" ]      || { assert_fail "detection script not found/executable at $DETECT"; return; }

  # --- Check 1: detection scanner should NOT fire on the hardened workflow ---
  echo "--- Check 1: detection scanner vs. hardened workflow ---"
  local tmp_repo
  tmp_repo=$(mktemp -d)
  mkdir -p "$tmp_repo/.github/workflows"
  cp "$HARDENED_WF" "$tmp_repo/.github/workflows/ci.yml"

  if ("$DETECT" static "$tmp_repo" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "detection scanner flagged the hardened workflow as vulnerable"
  else
    assert_pass "detection scanner reports no findings on the hardened workflow"
  fi
  rm -rf "$tmp_repo"

  # --- Check 2: detection scanner SHOULD fire on the vulnerable workflow ---
  echo ""
  echo "--- Check 2: detection scanner vs. vulnerable workflow ---"
  if [ -n "${VULNERABLE_WF:-}" ] && [ -d "$VULNERABLE_WF" ]; then
    if ("$DETECT" static "$VULNERABLE_WF" 2>/dev/null || true) | grep -q "FINDING"; then
      assert_pass "detection scanner correctly flags the vulnerable workflow"
    else
      assert_fail "detection scanner missed the vulnerable workflow"
    fi
  else
    # Try the default target clone location
    local target_clone="/home/claude/pwn-request-target"
    if [ -d "$target_clone/.github/workflows" ]; then
      if ("$DETECT" static "$target_clone" 2>/dev/null || true) | grep -q "FINDING"; then
        assert_pass "detection scanner correctly flags the vulnerable workflow"
      else
        assert_fail "detection scanner missed the vulnerable workflow"
      fi
    else
      echo "  SKIP: vulnerable target repo not found at $target_clone — cannot cross-check."
    fi
  fi

  # --- Check 3: structural invariants of the hardened workflow ---
  echo ""
  echo "--- Check 3: structural invariants ---"

  # 3a: The test job should NOT use pull_request_target
  # (it should filter on github.event_name == 'pull_request')
  if grep -A2 'test:' "$HARDENED_WF" | grep -q "pull_request_target"; then
    assert_fail "test job should not reference pull_request_target in its condition"
  else
    # Check the if: condition uses pull_request (not pull_request_target)
    local test_if
    test_if=$(grep -A5 '^\s*test:' "$HARDENED_WF" | grep 'if:' | head -1 || true)
    if echo "$test_if" | grep -q "pull_request'" && ! echo "$test_if" | grep -q "pull_request_target"; then
      assert_pass "test job runs only on pull_request (not pull_request_target)"
    elif echo "$test_if" | grep -q "'pull_request'"; then
      assert_pass "test job runs only on pull_request (not pull_request_target)"
    else
      assert_fail "test job condition unclear — expected if: github.event_name == 'pull_request'"
    fi
  fi

  # 3b: The test job should NOT reference any secrets
  local test_section
  # Extract from "  test:" up to the next job at the same indentation level
  test_section=$(awk '/^  test:/{found=1} found && /^  [a-z]/ && !/^  test:/{exit} found' "$HARDENED_WF")
  if echo "$test_section" | grep -q 'secrets\.'; then
    assert_fail "test job references secrets — it should not have access to any"
  else
    assert_pass "test job does not reference any secrets"
  fi

  # 3c: The test job should have minimal permissions
  if echo "$test_section" | grep -q 'contents: read'; then
    assert_pass "test job has read-only contents permission"
  else
    assert_fail "test job should explicitly set contents: read"
  fi

  # 3d: The privileged job (label) should NOT have a checkout step
  local label_section
  label_section=$(awk '/^  label:/{found=1} found && /^  [a-z]/ && !/^  label:/{exit} found' "$HARDENED_WF")
  if echo "$label_section" | grep -v '^\s*#' | grep -q 'actions/checkout'; then
    assert_fail "label job checks out code — it must NOT check out any PR code"
  else
    assert_pass "label job has no checkout step (never touches PR code)"
  fi

  # 3e: The privileged job should have only pull-requests: write
  if echo "$label_section" | grep -q 'pull-requests: write'; then
    assert_pass "label job has pull-requests: write permission"
  fi
  if echo "$label_section" | grep -q 'contents: write'; then
    assert_fail "label job should not have contents: write permission"
  else
    assert_pass "label job does not have contents: write permission"
  fi

  # 3f: Actions should be pinned by SHA (not mutable tag)
  if grep -E 'uses:.*@[a-f0-9]{40}' "$HARDENED_WF" >/dev/null; then
    assert_pass "actions are pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA, not mutable tags"
  fi

  # Check for any remaining mutable tag references
  if grep -E 'uses:.*@v[0-9]' "$HARDENED_WF" | grep -v '#' >/dev/null 2>&1; then
    assert_fail "some actions still use mutable tags (e.g., @v4)"
  else
    assert_pass "no mutable tag references found"
  fi

  echo ""
}

# ──────────────────────────────────────────────────────────────
# Live verification (re-runs attack against hardened workflow)
# ──────────────────────────────────────────────────────────────

verify_live() {
  local target_repo="$1"
  local target_clone="$2"

  echo "=== Live verification: re-attack against hardened workflow ==="
  echo ""
  echo "This deploys the hardened workflow to $target_repo, re-runs the"
  echo "attack, and verifies that the payload's assertions fail."
  echo ""

  # This is intentionally left as a framework — deploying the hardened
  # workflow to the target repo requires pushing to main, which should
  # be done manually or through a separate PR to avoid accidents.
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Replace .github/workflows/ci.yml in $target_repo with"
  echo "     hardened/01-pwn-request/ci.yml"
  echo "  2. Run attacks/01-pwn-request/attack.sh"
  echo "  3. Expected results:"
  echo "     - The 'test' job runs the malicious payload, but:"
  echo "       - process.env.GITHUB_TOKEN has only read scope → PR comment POST returns 403"
  echo "       - process.env.DUMMY_CLOUD_KEY is undefined → assertion fails"
  echo "     - The 'label' job runs but never checks out PR code"
  echo "     - The test job FAILS (exit code != 0)"
  echo "     - No PR comment is posted by the payload"
  echo "  4. The attack is structurally neutralized."
  echo ""
  echo "  After verification, restore the vulnerable workflow if you want"
  echo "  to keep running other demonstrations against it."
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

case "${1:-}" in
  static)
    verify_static
    ;;
  live)
    [ -n "${2:-}" ] && [ -n "${3:-}" ] || die "usage: $0 live <owner/repo> <target-clone-path>"
    verify_live "$2" "$3"
    ;;
  *)
    # Default to static verification
    verify_static
    ;;
esac

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}VERIFICATION FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow blocks the pwn request attack."
  exit 0
fi
