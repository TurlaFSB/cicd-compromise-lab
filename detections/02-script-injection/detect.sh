#!/usr/bin/env bash
# Detection script for scenario 02 — script injection via template expansion
#
# Detects GitHub Actions workflows that interpolate untrusted context values
# directly into run: shell steps using ${{ }} template expansion. This
# creates a command injection vulnerability because GitHub Actions performs
# the expansion as a literal string substitution before the shell parses
# the line.
#
# Two detection methods:
#   1. STATIC: scans workflow YAML files for ${{ <untrusted> }} inside run: blocks.
#   2. RUNTIME: queries the GitHub Actions API for recent workflow runs and
#      checks the workflow definitions for the same pattern.
#
# Requires: grep, awk. Runtime mode also requires gh CLI (authenticated).
# Usage:
#   ./detect.sh static  <path-to-repo>          # scan local workflows
#   ./detect.sh runtime <owner/repo> [--days N]  # query API (default: 7 days)
#
# Exit codes:
#   0 — no script injection pattern found
#   1 — script injection pattern DETECTED (findings printed to stdout)
#   2 — usage error or missing dependency

set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 2; }
warn()    { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
ok()      { echo -e "${GREEN}OK:${NC} $*"; }
finding() { echo -e "${RED}FINDING:${NC} $*"; FOUND=1; }

check_deps() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing dependency: $cmd"
  done
}

FOUND=0

# ──────────────────────────────────────────────────────────────
# Untrusted context patterns
#
# These are GitHub Actions context expressions that contain data
# an attacker can control (issue titles, PR titles, commit
# messages, branch names, comment bodies, etc.).
# ──────────────────────────────────────────────────────────────

# Build a single ERE pattern that matches any untrusted context
# inside a ${{ }} expression. Each alternative is a context path
# that an external actor can influence.
UNTRUSTED_CONTEXTS=(
  # Issue events
  'github\.event\.issue\.title'
  'github\.event\.issue\.body'
  'github\.event\.issue\.user\.login'
  # Pull request events
  'github\.event\.pull_request\.title'
  'github\.event\.pull_request\.body'
  'github\.event\.pull_request\.head\.ref'
  'github\.event\.pull_request\.head\.label'
  'github\.event\.pull_request\.head\.repo\.default_branch'
  # Discussion events
  'github\.event\.discussion\.title'
  'github\.event\.discussion\.body'
  # Comment events
  'github\.event\.comment\.body'
  'github\.event\.review\.body'
  'github\.event\.review_comment\.body'
  # Commit metadata
  'github\.event\.head_commit\.message'
  'github\.event\.head_commit\.author\.(name|email)'
  'github\.event\.commits\[.*\]\.message'
  # Branch names
  'github\.head_ref'
  'github\.event\.workflow_run\.head_branch'
  # Page events
  'github\.event\.pages\[.*\]\.page_name'
)

# Join into a single alternation
UNTRUSTED_RE=""
for ctx in "${UNTRUSTED_CONTEXTS[@]}"; do
  if [ -z "$UNTRUSTED_RE" ]; then
    UNTRUSTED_RE="$ctx"
  else
    UNTRUSTED_RE="${UNTRUSTED_RE}|${ctx}"
  fi
done

# Full pattern: ${{ ... untrusted_context ... }} — note we match the
# surrounding ${{ }} to confirm it's a template expression, not a comment.
INJECTION_RE='\$\{\{[^}]*('"${UNTRUSTED_RE}"')[^}]*\}\}'

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

    # Extract run: blocks and check for untrusted context interpolation.
    # We use awk to find lines that are inside a run: block (between
    # "run: |" or "run:" and the next step/key at the same indent level),
    # then check those lines for the injection pattern.
    #
    # This avoids false positives from ${{ }} used in env: mappings,
    # if: conditions, or with: inputs, which are safe contexts.

    local run_block_lines
    run_block_lines=$(awk '
      # Track when we enter a run: block
      /^[[:space:]]+run:[[:space:]]*[|>]?[[:space:]]*$/ || /^[[:space:]]+run:[[:space:]]+[^|>]/ {
        in_run = 1
        indent = 0
        match($0, /^[[:space:]]+/)
        if (RSTART == 1) indent = RLENGTH
        # For "run: |" or "run: >" (multi-line), the body starts on the next line
        if ($0 ~ /run:[[:space:]]*[|>][[:space:]]*$/) { next }
        # For "run: echo ..." (single-line), check this line
        print NR": "$0
        in_run = 0
        next
      }

      # Inside a multi-line run: block
      in_run {
        # Check if we have left the block (line at same or lesser indent that is a new key)
        current_indent = 0
        if (match($0, /^[[:space:]]+/)) current_indent = RLENGTH

        # Empty lines stay in the block
        if ($0 ~ /^[[:space:]]*$/) { print NR": "$0; next }

        # If indentation drops to or below the run: key level, we left the block
        if (current_indent <= indent && $0 ~ /[a-zA-Z_-]+:/) {
          in_run = 0
          next
        }

        print NR": "$0
      }
    ' "$wf" 2>/dev/null)

    if [ -z "$run_block_lines" ]; then
      continue
    fi

    # Check extracted run: block content for untrusted context interpolation
    local matches
    matches=$(echo "$run_block_lines" | grep -nE "$INJECTION_RE" 2>/dev/null || true)

    if [ -n "$matches" ]; then
      finding "$base: untrusted context interpolated directly in run: step (script injection)"
      echo "$matches" | while IFS= read -r match; do
        local line_num
        line_num=$(echo "$match" | cut -d: -f1)
        local content
        content=$(echo "$match" | cut -d: -f2-)
        echo "  Line $line_num:$content"

        # Extract which untrusted context was found
        local ctx_match
        ctx_match=$(echo "$content" | grep -oE "$INJECTION_RE" | head -1 || true)
        if [ -n "$ctx_match" ]; then
          echo "  Context: $ctx_match"
        fi
      done
      echo ""
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

  # Get all workflow files in the repo
  local workflows
  workflows=$(gh api "repos/$repo/actions/workflows" \
    --jq '.workflows[] | "\(.id) \(.path) \(.state)"' 2>/dev/null || true)

  if [ -z "$workflows" ]; then
    ok "no workflows found in $repo."
    return
  fi

  echo "  Checking workflow definitions for script injection patterns..."
  echo ""

  while IFS=' ' read -r wf_id wf_path wf_state; do
    [ "$wf_state" = "active" ] || continue

    # Fetch the workflow file content from the default branch
    local wf_content
    wf_content=$(gh api "repos/$repo/contents/$wf_path" \
      --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

    if [ -z "$wf_content" ]; then
      warn "could not read $wf_path — skipping."
      continue
    fi

    # Extract run: blocks and check for untrusted context
    local run_lines
    run_lines=$(echo "$wf_content" | awk '
      /^[[:space:]]+run:[[:space:]]*[|>]?[[:space:]]*$/ || /^[[:space:]]+run:[[:space:]]+[^|>]/ {
        in_run = 1
        indent = 0
        match($0, /^[[:space:]]+/)
        if (RSTART == 1) indent = RLENGTH
        if ($0 ~ /run:[[:space:]]*[|>][[:space:]]*$/) { next }
        print $0
        in_run = 0
        next
      }
      in_run {
        current_indent = 0
        if (match($0, /^[[:space:]]+/)) current_indent = RLENGTH
        if ($0 ~ /^[[:space:]]*$/) { print $0; next }
        if (current_indent <= indent && $0 ~ /[a-zA-Z_-]+:/) { in_run = 0; next }
        print $0
      }
    ' 2>/dev/null || true)

    if [ -z "$run_lines" ]; then
      continue
    fi

    local matches
    matches=$(echo "$run_lines" | grep -E "$INJECTION_RE" 2>/dev/null || true)

    if [ -n "$matches" ]; then
      finding "$wf_path: untrusted context interpolated directly in run: step"
      echo "  Workflow: $wf_path (id: $wf_id)"
      echo "  Dangerous lines:"
      echo "$matches" | while IFS= read -r line; do
        echo "    $line"
      done

      # Check recent runs
      local recent_runs
      recent_runs=$(gh api "repos/$repo/actions/workflows/$wf_id/runs?created=>$since&per_page=5" \
        --jq '.workflow_runs | length' 2>/dev/null || echo "0")
      echo "  Recent runs (last $days days): $recent_runs"
      echo ""
    fi
  done <<< "$workflows"
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
  echo -e "${RED}=== SCRIPT INJECTION PATTERN DETECTED ===${NC}"
  echo "See: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
  echo "Fix: hardened/02-script-injection/triage.yml in cicd-compromise-lab"
  exit 1
else
  echo ""
  ok "no script injection pattern detected."
  exit 0
fi
