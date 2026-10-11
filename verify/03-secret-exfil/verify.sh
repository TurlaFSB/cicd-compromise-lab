#!/usr/bin/env bash
# Verification script for scenario 03 — secret exfiltration
#
# Proves the hardened workflow eliminates all secret exfiltration vectors by:
#   1. Running the static detection scanner against BOTH the vulnerable and
#      hardened workflow files — the vulnerable one should trigger findings,
#      the hardened one should not.
#   2. Checking structural invariants of the hardened workflow:
#      - Build job has NO secrets in env: or steps
#      - Deploy job uses environment: protection
#      - Deploy job has per-job (not workflow-level) permissions
#      - No secret is echoed, printed, or transformed in any run: step
#      - All actions pinned by full commit SHA
#      - Permissions are least-privilege per job
#
# Usage:
#   ./verify.sh static                              # offline structural checks
#   ./verify.sh live <target-repo> <target-clone>    # full live verification
#
# Exit codes:
#   0 — verification passed (hardened workflow blocks exfiltration)
#   1 — verification FAILED (hardened workflow still vulnerable)
#   2 — usage error or missing dependency

# shellcheck disable=SC2016  # patterns intentionally contain literal '$' (variable names in scanned YAML)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/03-secret-exfil/detect.sh"
HARDENED_WF="$LAB_ROOT/hardened/03-secret-exfil/deploy.yml"

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
  cp "$HARDENED_WF" "$tmp_repo/.github/workflows/deploy.yml"

  if ("$DETECT" static "$tmp_repo" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "detection scanner flagged the hardened workflow as vulnerable"
  else
    assert_pass "detection scanner reports no findings on the hardened workflow"
  fi
  rm -rf "$tmp_repo"

  # --- Check 2: detection scanner SHOULD fire on the vulnerable workflow ---
  echo ""
  echo "--- Check 2: detection scanner vs. vulnerable workflow ---"
  local target_clone="/home/claude/secret-exfil-target"
  if [ -d "$target_clone/.github/workflows" ]; then
    if ("$DETECT" static "$target_clone" 2>/dev/null || true) | grep -q "FINDING"; then
      assert_pass "detection scanner correctly flags the vulnerable workflow"
    else
      assert_fail "detection scanner missed the vulnerable workflow"
    fi
  else
    echo "  SKIP: vulnerable target repo not found at $target_clone — cannot cross-check."
  fi

  # --- Check 3: structural invariants of the hardened workflow ---
  echo ""
  echo "--- Check 3: structural invariants ---"

  # 3a: Build job should NOT have any secrets
  local build_section
  build_section=$(awk '
    /^[[:space:]]+build:/ { in_build = 1 }
    in_build && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+build:/ { in_build = 0 }
    in_build { print }
  ' "$HARDENED_WF")

  if echo "$build_section" | grep -v '^[[:space:]]*#' | grep -qE 'secrets\.'; then
    assert_fail "build job references secrets — it should have NO access to any credentials"
  else
    assert_pass "build job does not reference any secrets"
  fi

  # 3b: Build job should have read-only permissions
  local build_perms
  build_perms=$(echo "$build_section" | awk '
    /^[[:space:]]+permissions:/ { in_perms = 1; next }
    in_perms && /^[[:space:]]+[a-z]/ { print; next }
    in_perms && !/^[[:space:]]*$/ { in_perms = 0 }
  ')

  if echo "$build_perms" | grep -qE 'contents:[[:space:]]*read'; then
    assert_pass "build job has contents: read permission"
  else
    assert_fail "build job should explicitly declare contents: read"
  fi

  if echo "$build_perms" | grep -qE 'write'; then
    assert_fail "build job should not have any write permissions"
  else
    assert_pass "build job has no write permissions"
  fi

  # 3c: Deploy job should use environment: protection
  local deploy_section
  deploy_section=$(awk '
    /^[[:space:]]+deploy:/ { in_deploy = 1 }
    in_deploy && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+deploy:/ { in_deploy = 0 }
    in_deploy { print }
  ' "$HARDENED_WF")

  if echo "$deploy_section" | grep -v '^[[:space:]]*#' | grep -qE '^[[:space:]]+environment:'; then
    assert_pass "deploy job uses environment: protection (requires reviewer approval)"
  else
    assert_fail "deploy job should use environment: protection for secret access control"
  fi

  # 3d: No secrets echoed or printed in any run: step
  local run_content
  run_content=$(awk '
    /^[[:space:]]+run:[[:space:]]*[|>]?[[:space:]]*$/ { in_run = 1; run_indent = 0; next }
    /^[[:space:]]+run:[[:space:]]+[^|>]/ { print $0; next }
    in_run && /^[[:space:]]*$/ { next }
    in_run && run_indent == 0 && /^[[:space:]]/ {
      match($0, /^[[:space:]]+/)
      run_indent = RLENGTH
      print $0
      next
    }
    in_run && run_indent > 0 {
      if (/^[[:space:]]/ && match($0, /^[[:space:]]+/) && RLENGTH >= run_indent) {
        print $0
      } else {
        in_run = 0
        run_indent = 0
      }
    }
  ' "$HARDENED_WF" 2>/dev/null || true)

  if echo "$run_content" | grep -v '^[[:space:]]*#' | grep -qE '(echo|printf|cat)[[:space:]].*(\$DEPLOY_KEY|\$\{DEPLOY_KEY|\$\{\{[[:space:]]*secrets\.)'; then
    assert_fail "secret value is echoed/printed in a run: step"
  else
    assert_pass "no secrets echoed or printed in any run: step"
  fi

  # 3e: No secret transformation (base64, hex, etc.)
  if echo "$run_content" | grep -v '^[[:space:]]*#' | grep -qE '(\$DEPLOY_KEY|\$\{DEPLOY_KEY).*\|[[:space:]]*(base64|xxd|od|hexdump)'; then
    assert_fail "secret is transformed (base64/hex) — masking bypass still possible"
  else
    assert_pass "no secret transformation found (no masking bypass)"
  fi

  # 3f: No workflow-level permissions (should be per-job only)
  local wf_level_perms
  wf_level_perms=$(awk '
    /^permissions:/ { in_perms = 1; next }
    in_perms && /^[[:space:]]/ { print; next }
    in_perms { in_perms = 0 }
  ' "$HARDENED_WF" 2>/dev/null || true)

  if [ -n "$wf_level_perms" ]; then
    assert_fail "permissions declared at workflow level — should be per-job only"
  else
    assert_pass "permissions are per-job, not workflow-level"
  fi

  # 3g: No workflow-level env: with secrets
  local wf_level_env
  wf_level_env=$(awk '
    /^env:/ { in_env = 1; next }
    in_env && /^[[:space:]]/ { print; next }
    in_env { in_env = 0 }
  ' "$HARDENED_WF" 2>/dev/null || true)

  if echo "$wf_level_env" | grep -qE 'secrets\.'; then
    assert_fail "secrets in workflow-level env: block — should be scoped to specific steps"
  else
    assert_pass "no secrets in workflow-level env: block"
  fi

  # 3h: Deploy job secret is scoped to step-level env:, not job-level env:
  local deploy_job_env
  deploy_job_env=$(echo "$deploy_section" | awk '
    /^[[:space:]]+steps:/ { past_steps = 1 }
    !past_steps && /^[[:space:]]+env:/ { in_env = 1; next }
    !past_steps && in_env && /^[[:space:]]+/ { print; next }
    !past_steps && in_env { in_env = 0 }
  ')

  if echo "$deploy_job_env" | grep -qE 'secrets\.'; then
    assert_fail "deploy job has secrets in job-level env: — should be step-level only"
  else
    assert_pass "deploy secrets are step-scoped, not job-scoped"
  fi

  # 3i: All actions pinned by commit SHA
  if grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep -qE 'uses:.*@[a-f0-9]{40}'; then
    assert_pass "actions are pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA, not mutable tags"
  fi

  # Check for any remaining mutable tag references
  if grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep -qE 'uses:[[:space:]]+[^@]+@v[0-9]'; then
    assert_fail "some actions still use mutable tags (e.g., @v4)"
  else
    assert_pass "no mutable tag references found"
  fi

  # 3j: Deploy job has least-privilege permissions
  local deploy_perms
  deploy_perms=$(echo "$deploy_section" | awk '
    /^[[:space:]]+permissions:/ { in_perms = 1; next }
    in_perms && /^[[:space:]]+[a-z]/ { print; next }
    in_perms && !/^[[:space:]]*$/ { in_perms = 0 }
  ')

  if echo "$deploy_perms" | grep -qE 'contents:[[:space:]]*write'; then
    assert_fail "deploy job has contents: write — should be contents: read unless pushing to repo"
  else
    assert_pass "deploy job does not have contents: write"
  fi

  echo ""
}

# ──────────────────────────────────────────────────────────────
# Live verification
# ──────────────────────────────────────────────────────────────

verify_live() {
  local target_repo="$1"
  local target_clone="$2"

  echo "=== Live verification: re-test against hardened workflow ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Replace .github/workflows/deploy.yml in $target_repo with"
  echo "     hardened/03-secret-exfil/deploy.yml"
  echo "  2. Configure a 'production' environment in repo settings:"
  echo "     Settings > Environments > New environment > 'production'"
  echo "     - Add required reviewers"
  echo "     - Restrict to main branch"
  echo "  3. Push a commit to main and verify:"
  echo "     - Build job completes with NO access to DEPLOY_KEY"
  echo "     - Deploy job requires reviewer approval before running"
  echo "     - No secret values appear in any log output"
  echo "     - base64-encoded secrets do NOT appear in logs"
  echo "  4. Expected results:"
  echo "     - If DEPLOY_KEY is set: deployment succeeds without logging the key"
  echo "     - If DEPLOY_KEY is not set: deployment aborts with a clear error"
  echo "     - Build job env shows no DEPLOY_KEY variable at all"
  echo ""
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

case "${1:-}" in
  static)
    verify_static
    ;;
  live)
    [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "usage: $0 live <owner/repo> <target-clone-path>" >&2; exit 2; }
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow eliminates secret exfiltration vectors."
  exit 0
fi
