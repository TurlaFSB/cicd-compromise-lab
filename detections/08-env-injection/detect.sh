#!/usr/bin/env bash
# Detection script for scenario 08 — GITHUB_ENV / GITHUB_PATH injection
#
# Finds workflows that write untrusted data, or dangerous variables, into the
# runner's environment files ($GITHUB_ENV, $GITHUB_PATH), where they become
# environment variables or PATH entries for every later step in the job.
#
# Detection vectors:
#   1. UNTRUSTED TO GITHUB_ENV/PATH: a run: line writes attacker-controlled
#      context (github.event.issue.*, pull_request.*, comment.*, head_ref,
#      etc.) to $GITHUB_ENV or $GITHUB_PATH. A crafted value can inject extra
#      KEY=VALUE lines or PATH entries.
#   2. DANGEROUS VAR TO GITHUB_ENV: a step sets an execution-hijacking
#      variable (NODE_OPTIONS, LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV,
#      PYTHONPATH, PERL5LIB) via $GITHUB_ENV — the mechanism an injection
#      ultimately abuses, and dangerous even when the value looks static.
#   3. UNTRUSTED TO GITHUB_PATH: attacker-controlled context appended to
#      $GITHUB_PATH, prepending a directory to PATH so a planted shim runs.
#
# Two detection methods:
#   1. STATIC: scans local workflow YAML files.
#   2. RUNTIME: fetches workflow files from a repo via the GitHub API.
#
# Requires: bash 4+, grep, awk. Optional: gh CLI (runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
#
# Exit codes:
#   0 — no env-injection pattern found
#   1 — env-injection pattern DETECTED
#   2 — usage error or missing dependency

# shellcheck disable=SC2016  # patterns intentionally contain literal '$' (GITHUB_ENV etc. in scanned YAML)
set -euo pipefail

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

# Attacker-controlled GitHub Actions contexts.
UNTRUSTED='github\.event\.(issue|pull_request|comment|review|discussion|head_commit|pull_request_target)|github\.head_ref'
# Execution-hijacking environment variables.
DANGER='(NODE_OPTIONS|LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|PYTHONPATH|PERL5LIB|GEM_PATH|DYLD_INSERT_LIBRARIES)'

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0
  local body
  body=$(grep -v '^[[:space:]]*#' "$wf")

  # Lines that write to the runner environment files.
  local env_writes
  env_writes=$(echo "$body" | grep -E '>>[[:space:]]*"?\$\{?GITHUB_(ENV|PATH)\}?"?' || true)

  if [ -z "$env_writes" ]; then
    ok "$base: no writes to GITHUB_ENV/GITHUB_PATH."
    return
  fi

  # ── Vector 1: untrusted context written to GITHUB_ENV ──
  if echo "$env_writes" | grep -qE '\$\{\{[^}]*('"$UNTRUSTED"')' \
     && echo "$env_writes" | grep -qE 'GITHUB_ENV'; then
    finding "$base: UNTRUSTED TO GITHUB_ENV — attacker-controlled context written to \$GITHUB_ENV."
    echo "  A crafted value injects extra KEY=VALUE lines (NODE_OPTIONS, LD_PRELOAD)."
    echo "  Matched:"
    echo "$env_writes" | grep -E '\$\{\{[^}]*('"$UNTRUSTED"')' | grep GITHUB_ENV | sed 's/^/    /' | head -3
    echo ""
    file_findings=1
  fi

  # ── Vector 3: untrusted context written to GITHUB_PATH ──
  if echo "$env_writes" | grep -qE '\$\{\{[^}]*('"$UNTRUSTED"')' \
     && echo "$env_writes" | grep -qE 'GITHUB_PATH'; then
    finding "$base: UNTRUSTED TO GITHUB_PATH — attacker-controlled context prepended to PATH."
    echo "  A planted directory on PATH lets a shim (npm, node, python) hijack later steps."
    echo ""
    file_findings=1
  fi

  # ── Vector 2: dangerous execution-hijack var set via GITHUB_ENV ──
  if echo "$env_writes" | grep -qE '^[^#]*'"$DANGER"'=' \
     && echo "$env_writes" | grep -qE 'GITHUB_ENV'; then
    finding "$base: DANGEROUS VAR TO GITHUB_ENV — an execution-hijacking variable is set via \$GITHUB_ENV."
    echo "  NODE_OPTIONS/LD_PRELOAD/BASH_ENV and similar alter how later steps execute code."
    echo ""
    file_findings=1
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: GITHUB_ENV/GITHUB_PATH writes use only trusted, static values."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for GITHUB_ENV/PATH injection: $wf_dir ==="
  local count=0
  for wf in "$wf_dir"/*.yml "$wf_dir"/*.yaml; do
    [ -f "$wf" ] || continue
    count=$((count + 1))
    echo ""
    echo "--- $(basename "$wf") ---"
    analyze_workflow "$wf" "$(basename "$wf")"
  done
  [ "$count" -gt 0 ] || warn "no workflow files found in $wf_dir"
}

detect_runtime() {
  local repo="$1"
  check_deps gh
  echo "=== Runtime scan for GITHUB_ENV/PATH injection: $repo ==="

  local wf_files
  wf_files=$(gh api "repos/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null || true)
  [ -n "$wf_files" ] || { warn "no workflow files found in $repo"; return; }

  while IFS= read -r wf_name; do
    local wf_yaml tmp
    wf_yaml=$(gh api "repos/$repo/contents/.github/workflows/$wf_name" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)
    [ -n "$wf_yaml" ] || { warn "could not read $wf_name"; continue; }
    tmp=$(mktemp)
    printf '%s\n' "$wf_yaml" > "$tmp"
    echo ""
    echo "--- $wf_name ---"
    analyze_workflow "$tmp" "$wf_name"
    rm -f "$tmp"
  done <<< "$wf_files"
}

case "${1:-}" in
  static)
    [ -n "${2:-}" ] || die "usage: $0 static <path-to-repo>"
    detect_static "$2"
    ;;
  runtime)
    [ -n "${2:-}" ] || die "usage: $0 runtime <owner/repo>"
    detect_runtime "$2"
    ;;
  *)
    die "usage: $0 {static <path>|runtime <owner/repo>}"
    ;;
esac

echo ""
if [ "$FOUND" -eq 1 ]; then
  echo -e "${RED}=== GITHUB_ENV / GITHUB_PATH INJECTION DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution"
  echo "Fix: pass untrusted data through step-scoped env:, never echo it into GITHUB_ENV/GITHUB_PATH."
  echo "     See hardened/08-env-injection/ in cicd-compromise-lab"
  exit 1
else
  ok "no GITHUB_ENV/GITHUB_PATH injection patterns detected."
  exit 0
fi
