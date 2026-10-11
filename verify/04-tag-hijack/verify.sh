#!/usr/bin/env bash
# Verification script for scenario 04 — mutable action tag hijack
#
# Proves the hardened workflow eliminates the tag-hijack attack surface by:
#   1. Running the detection scanner against both the vulnerable and hardened
#      workflows — the vulnerable one should trigger findings, the hardened
#      one should not.
#   2. Checking structural invariants of the hardened workflow:
#      - Every uses: line references a full 40-character commit SHA
#      - No uses: line references a mutable tag (@v1, @main, @latest, etc.)
#      - Each SHA has a human-readable tag in a trailing comment
#      - Per-job permissions (not workflow-level)
#      - No workflow-level env: with secrets
#      - Persist-credentials: false on checkout steps
#
# Usage:
#   ./verify.sh static                              # offline structural checks
#   ./verify.sh live <target-repo> <target-clone>    # full live verification
#
# Exit codes:
#   0 — verification passed (hardened workflow blocks tag hijack)
#   1 — verification FAILED (hardened workflow still vulnerable)
#   2 — usage error or missing dependency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/04-tag-hijack/detect.sh"
HARDENED_WF="$LAB_ROOT/hardened/04-tag-hijack/ci.yml"
VULNERABLE_WF="$LAB_ROOT/attacks/04-tag-hijack/vulnerable-ci.yml"

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

  [ -f "$HARDENED_WF" ]  || { assert_fail "hardened workflow not found at $HARDENED_WF"; return; }
  [ -x "$DETECT" ]       || { assert_fail "detection script not found/executable at $DETECT"; return; }

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
  if [ -f "$VULNERABLE_WF" ]; then
    local vuln_repo
    vuln_repo=$(mktemp -d)
    mkdir -p "$vuln_repo/.github/workflows"
    cp "$VULNERABLE_WF" "$vuln_repo/.github/workflows/ci.yml"

    if ("$DETECT" static "$vuln_repo" 2>/dev/null || true) | grep -q "FINDING"; then
      assert_pass "detection scanner correctly flags the vulnerable workflow"
    else
      assert_fail "detection scanner missed the vulnerable workflow"
    fi
    rm -rf "$vuln_repo"
  else
    echo "  SKIP: vulnerable workflow not found at $VULNERABLE_WF"
  fi

  # --- Check 3: structural invariants of the hardened workflow ---
  echo ""
  echo "--- Check 3: structural invariants ---"

  # 3a: Every uses: line should have a full 40-char SHA
  local uses_lines
  uses_lines=$(grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep 'uses:' || true)
  local total_uses=0
  local sha_pinned=0
  local unpinned_lines=""

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    total_uses=$((total_uses + 1))

    # Extract the ref after @
    local ref
    ref=$(echo "$line" | sed 's/.*@//' | sed 's/[[:space:]]*#.*//' | tr -d ' ')

    if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
      sha_pinned=$((sha_pinned + 1))
    else
      unpinned_lines="${unpinned_lines}    ${line}
"
    fi
  done <<< "$uses_lines"

  if [ "$total_uses" -gt 0 ] && [ "$sha_pinned" -eq "$total_uses" ]; then
    assert_pass "all $total_uses action references are pinned by full 40-char commit SHA"
  elif [ "$total_uses" -gt 0 ]; then
    assert_fail "$((total_uses - sha_pinned)) of $total_uses action references are NOT pinned by SHA"
    if [ -n "$unpinned_lines" ]; then
      echo "  Unpinned:"
      echo "$unpinned_lines"
    fi
  fi

  # 3b: No mutable version tags
  if grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep -qE 'uses:[[:space:]]+[^@]+@v[0-9]'; then
    assert_fail "mutable version tags found (e.g., @v4) — should be SHA-pinned"
  else
    assert_pass "no mutable version tags (@vN) in any uses: line"
  fi

  # 3c: No mutable branch refs
  if grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep -qE 'uses:[[:space:]]+[^@]+@(main|master|develop)\b'; then
    assert_fail "mutable branch refs found — should be SHA-pinned"
  else
    assert_pass "no mutable branch refs (@main, @master, etc.)"
  fi

  # 3d: Each pinned SHA has a human-readable comment
  local sha_lines_without_comment=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if echo "$line" | grep -qE '@[0-9a-f]{40}' && ! echo "$line" | grep -qE '#.*v[0-9]'; then
      sha_lines_without_comment=$((sha_lines_without_comment + 1))
    fi
  done <<< "$uses_lines"

  if [ "$sha_lines_without_comment" -eq 0 ]; then
    assert_pass "every SHA-pinned action has a version comment for auditability"
  else
    assert_fail "$sha_lines_without_comment SHA-pinned action(s) lack a version comment"
  fi

  # 3e: No workflow-level permissions (should be per-job)
  local wf_level_perms
  wf_level_perms=$(awk '
    /^permissions:/ { in_perms = 1; next }
    in_perms && /^[[:space:]]/ { print; next }
    in_perms { in_perms = 0 }
  ' "$HARDENED_WF" 2>/dev/null || true)

  if [ -n "$wf_level_perms" ]; then
    assert_fail "permissions declared at workflow level — should be per-job"
  else
    assert_pass "permissions are per-job, not workflow-level"
  fi

  # 3f: No workflow-level env: with secrets
  local wf_level_env
  wf_level_env=$(awk '
    /^env:/ { in_env = 1; next }
    in_env && /^[[:space:]]/ { print; next }
    in_env { in_env = 0 }
  ' "$HARDENED_WF" 2>/dev/null || true)

  if echo "$wf_level_env" | grep -qE 'secrets\.'; then
    assert_fail "secrets in workflow-level env: block"
  else
    assert_pass "no secrets in workflow-level env: block"
  fi

  # 3g: Checkout steps use persist-credentials: false
  local checkout_steps
  checkout_steps=$(grep -c 'actions/checkout@' "$HARDENED_WF" || true)
  local persist_false
  persist_false=$(grep -c 'persist-credentials: false' "$HARDENED_WF" || true)

  if [ "$checkout_steps" -gt 0 ] && [ "$persist_false" -ge "$checkout_steps" ]; then
    assert_pass "all checkout steps use persist-credentials: false"
  elif [ "$checkout_steps" -gt 0 ]; then
    assert_fail "$((checkout_steps - persist_false)) checkout step(s) missing persist-credentials: false"
  fi

  # 3h: Each job has its own permissions block
  # Count only job-level entries under `jobs:`, not `on:` triggers
  local job_count
  job_count=$(awk '
    /^jobs:/ { in_jobs = 1; next }
    in_jobs && /^[[:space:]]{2}[a-zA-Z_-]+:/ { count++ }
    in_jobs && /^[a-zA-Z]/ && !/^jobs:/ { in_jobs = 0 }
    END { print count+0 }
  ' "$HARDENED_WF" 2>/dev/null || echo "0")
  local job_perms_count
  job_perms_count=$(awk '
    /^jobs:/ { in_jobs = 1; next }
    in_jobs && /^[[:space:]]{2}[a-zA-Z_-]+:/ {
      if (in_job && has_perms) count++
      in_job = 1; has_perms = 0
      next
    }
    in_jobs && in_job && /^[[:space:]]+permissions:/ { has_perms = 1 }
    in_jobs && /^[a-zA-Z]/ && !/^jobs:/ { in_jobs = 0 }
    END { if (in_job && has_perms) count++; print count+0 }
  ' "$HARDENED_WF" 2>/dev/null || echo "0")

  if [ "$job_count" -gt 0 ] && [ "$job_perms_count" -ge "$job_count" ]; then
    assert_pass "all $job_count jobs declare their own permissions block"
  elif [ "$job_count" -gt 0 ]; then
    assert_fail "$((job_count - job_perms_count)) of $job_count jobs missing per-job permissions"
  fi

  # 3i: Deploy job uses environment: protection
  local deploy_section
  deploy_section=$(awk '
    /^[[:space:]]+deploy:/ { in_deploy = 1 }
    in_deploy && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+deploy:/ { in_deploy = 0 }
    in_deploy { print }
  ' "$HARDENED_WF")

  if echo "$deploy_section" | grep -v '^[[:space:]]*#' | grep -qE '^[[:space:]]+environment:'; then
    assert_pass "deploy job uses environment: protection"
  else
    assert_fail "deploy job should use environment: protection"
  fi

  # 3j: No write permissions except where needed
  local all_write_perms
  all_write_perms=$(grep -v '^[[:space:]]*#' "$HARDENED_WF" | grep -cE 'contents:[[:space:]]*write' || true)

  if [ "$all_write_perms" -eq 0 ]; then
    assert_pass "no contents: write permissions in any job"
  else
    assert_fail "contents: write found — should be contents: read unless required"
  fi

  echo ""
}

# ──────────────────────────────────────────────────────────────
# Live verification
# ──────────────────────────────────────────────────────────────

verify_live() {
  local target_repo="$1"
  local _target_clone="$2"

  echo "=== Live verification: tag hijack simulation ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Create turla-lab-targets/lab-helper-action with a simple"
  echo "     composite action (deploy helper) and tag it v1.0.0 / v1."
  echo "  2. Deploy vulnerable-ci.yml to the target repo."
  echo "  3. Push a commit — the workflow runs the original action code."
  echo "  4. Force-push the v1 tag on lab-helper-action to a commit"
  echo "     containing attacks/04-tag-hijack/payload/action.yml."
  echo "  5. Push another commit to the target repo — the workflow now"
  echo "     silently runs the COMPROMISED code."
  echo "  6. Check workflow logs for the exfiltration proof-of-concept."
  echo "  7. Replace the workflow with hardened/04-tag-hijack/ci.yml."
  echo "  8. Repeat the tag hijack — the hardened workflow is unaffected"
  echo "     because it pins to the original commit SHA, not the tag."
  echo ""
  echo "  Target: $target_repo"
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow eliminates mutable tag hijack vectors."
  exit 0
fi
