#!/usr/bin/env bash
# Detection script for scenario 01 — pwn request
#
# Two detection methods:
#   1. STATIC: scans workflow YAML files for the dangerous pattern
#      (pull_request_target + checkout PR head + code execution).
#   2. RUNTIME: queries the GitHub Actions API for completed
#      pull_request_target runs and checks whether the workflow
#      definition they ran contains the vulnerable pattern.
#
# Requires: gh CLI (authenticated), yq (for YAML parsing), grep.
# Usage:
#   ./detect.sh static  <path-to-repo>          # scan local workflows
#   ./detect.sh runtime <owner/repo> [--days N]  # query API (default: 7 days)
#
# Exit codes:
#   0 — no pwn request pattern found
#   1 — pwn request pattern DETECTED (findings printed to stdout)
#   2 — usage error or missing dependency

set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

die()   { echo -e "${RED}ERROR:${NC} $*" >&2; exit 2; }
warn()  { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
ok()    { echo -e "${GREEN}OK:${NC} $*"; }
finding() { echo -e "${RED}FINDING:${NC} $*"; FOUND=1; }

check_deps() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing dependency: $cmd"
  done
}

FOUND=0

# ──────────────────────────────────────────────────────────────
# Method 1: Static analysis of workflow YAML files
# ──────────────────────────────────────────────────────────────

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"

  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan: $wf_dir ==="

  for wf in "$wf_dir"/*.yml "$wf_dir"/*.yaml; do
    [ -f "$wf" ] || continue
    local base
    base=$(basename "$wf")

    # Check 1: does the workflow trigger on pull_request_target?
    if ! grep -qE '^\s*pull_request_target\s*:?' "$wf"; then
      continue
    fi

    # Check 2: does it check out the PR's head commit?
    local has_pr_checkout=0
    if grep -qE 'github\.event\.pull_request\.head\.(sha|ref)' "$wf" ||
       grep -qE 'github\.head_ref' "$wf"; then
      has_pr_checkout=1
    fi

    if [ "$has_pr_checkout" -eq 0 ]; then
      ok "$base: triggers on pull_request_target but does not check out PR head — safe pattern."
      continue
    fi

    # Check 3: does it execute code after checkout (run: steps)?
    local has_run_step=0
    if grep -qE '^\s+run:\s' "$wf"; then
      has_run_step=1
    fi

    if [ "$has_run_step" -eq 1 ]; then
      finding "$base: VULNERABLE — pull_request_target + PR head checkout + code execution."
      echo "  Trigger:  pull_request_target"
      echo "  Checkout: $(grep -nE 'github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref' "$wf" | head -1)"
      echo "  Executes: $(grep -nE '^\s+run:\s' "$wf" | head -1)"
      echo ""
    else
      warn "$base: pull_request_target + PR head checkout but no run: step found. Review manually."
    fi
  done
}

# ──────────────────────────────────────────────────────────────
# Method 2: Runtime detection via GitHub Actions API
# ──────────────────────────────────────────────────────────────

detect_runtime() {
  local repo="$1"
  local days="${2:-7}"
  local since
  since=$(date -u -d "$days days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
          date -u -v-"${days}d" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
          die "cannot compute date offset")

  check_deps gh

  echo "=== Runtime scan: $repo (last $days days) ==="

  # Find all pull_request_target runs in the time window
  local runs
  runs=$(gh api "repos/$repo/actions/runs?event=pull_request_target&created=>$since&per_page=100" \
    --jq '.workflow_runs[] | "\(.id) \(.head_branch) \(.conclusion) \(.workflow_id)"' 2>/dev/null || true)

  if [ -z "$runs" ]; then
    ok "no pull_request_target runs found in the last $days days."
    return
  fi

  local run_count
  run_count=$(echo "$runs" | wc -l)
  echo "  Found $run_count pull_request_target run(s). Checking workflow definitions..."

  while IFS=' ' read -r run_id head_branch conclusion workflow_id; do
    # Fetch the workflow file content to check if it checks out PR code
    local wf_content
    wf_content=$(gh api "repos/$repo/actions/workflows/$workflow_id" \
      --jq '.path' 2>/dev/null || true)

    if [ -z "$wf_content" ]; then
      warn "run $run_id: could not determine workflow path."
      continue
    fi

    # Try to fetch the workflow file from the default branch
    local wf_yaml
    wf_yaml=$(gh api "repos/$repo/contents/$wf_content" \
      --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

    if [ -z "$wf_yaml" ]; then
      warn "run $run_id: could not read workflow file $wf_content."
      continue
    fi

    local has_pr_checkout=0
    if echo "$wf_yaml" | grep -qE 'github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref'; then
      has_pr_checkout=1
    fi

    local has_run_step=0
    if echo "$wf_yaml" | grep -qE '^\s+run:\s'; then
      has_run_step=1
    fi

    if [ "$has_pr_checkout" -eq 1 ] && [ "$has_run_step" -eq 1 ]; then
      finding "run $run_id: workflow $wf_content checks out PR head and executes code under pull_request_target."
      echo "  Run:        https://github.com/$repo/actions/runs/$run_id"
      echo "  Branch:     $head_branch"
      echo "  Conclusion: $conclusion"
      echo "  Workflow:   $wf_content"
      echo ""

      # Check if the PR was from an external contributor (fork)
      local pr_head_repo
      pr_head_repo=$(gh api "repos/$repo/actions/runs/$run_id" \
        --jq '.head_repository.full_name' 2>/dev/null || true)

      if [ -n "$pr_head_repo" ] && [ "$pr_head_repo" != "$repo" ]; then
        echo "  ⚠  PR was from a FORK ($pr_head_repo) — external code ran with base repo privileges."
      fi
    fi
  done <<< "$runs"
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

case "${1:-}" in
  static)
    [ -n "${2:-}" ] || die "usage: $0 static <path-to-repo>"
    detect_static "$2"
    ;;
  runtime)
    [ -n "${2:-}" ] || die "usage: $0 runtime <owner/repo> [--days N]"
    days=7
    if [ "${3:-}" = "--days" ] && [ -n "${4:-}" ]; then
      days="$4"
    fi
    detect_runtime "$2" "$days"
    ;;
  *)
    die "usage: $0 {static <path>|runtime <owner/repo> [--days N]}"
    ;;
esac

if [ "$FOUND" -eq 1 ]; then
  echo ""
  echo -e "${RED}=== PWN REQUEST PATTERN DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution"
  echo "Fix: hardened/01-pwn-request/ci.yml in cicd-compromise-lab"
  exit 1
else
  echo ""
  ok "no pwn request pattern detected."
  exit 0
fi
