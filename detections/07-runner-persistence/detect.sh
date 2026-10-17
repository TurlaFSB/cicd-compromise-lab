#!/usr/bin/env bash
# Detection script for scenario 07 — self-hosted runner persistence
#
# Finds workflows that run untrusted code on self-hosted runners, where a
# reused (non-ephemeral) runner lets an implant survive from a fork PR's job
# into later, trusted jobs on the same machine.
#
# Detection vectors:
#   1. UNTRUSTED ON SELF-HOSTED: a job triggered by pull_request or
#      pull_request_target runs on a self-hosted runner (runs-on: self-hosted,
#      or a non-hosted custom label).
#   2. SELF-HOSTED + CHECKOUT PR CODE: a self-hosted job checks out and runs
#      PR-controlled code (npm ci/test, make, bash scripts), the exact path
#      that lets a fork drop a persistence implant.
#   3. PERSISTENCE-WRITING STEP: a step writes to a location that outlives the
#      workspace on a reused runner (crontab, ~/.bashrc/.profile, systemd
#      --user, /etc, autostart), which only matters on self-hosted runners.
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
#   0 — no runner persistence pattern found
#   1 — runner persistence pattern DETECTED
#   2 — usage error or missing dependency

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

triggered_untrusted() {
  awk '/^on:/{f=1;next} f&&/^[^[:space:]#]/{f=0} f{print}' "$1" \
    | grep -qE '(^|[[:space:],])(pull_request|pull_request_target)([[:space:],:]|$)'
}

uses_self_hosted() {
  # Explicit self-hosted, or a runs-on that is not a known GitHub-hosted label.
  grep -qE '^[[:space:]]*runs-on:.*self-hosted' "$1" && return 0
  grep -qE '^[[:space:]]*runs-on:' "$1" || return 1
  ! grep -qE '^[[:space:]]*runs-on:[[:space:]]*\[?[[:space:]]*["'"'"']?(ubuntu|windows|macos)-' "$1"
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  if ! grep -qE '^[[:space:]]*runs-on:' "$wf"; then
    ok "$base: no runs-on — not in scope."
    return
  fi

  local untrusted=0 selfhosted=0
  triggered_untrusted "$wf" && untrusted=1
  uses_self_hosted "$wf" && selfhosted=1

  # ── Vector 1: untrusted trigger on a self-hosted runner ──
  if [ "$untrusted" -eq 1 ] && [ "$selfhosted" -eq 1 ]; then
    finding "$base: UNTRUSTED ON SELF-HOSTED — pull_request(_target) code runs on a self-hosted runner."
    echo "  A reused runner carries an implant from a fork PR's job into later jobs."
    echo "  Run untrusted code on GitHub-hosted runners, or ephemeral self-hosted ones."
    echo ""
    file_findings=1

    # ── Vector 2: and it checks out + runs PR code ──
    if grep -qE 'uses:[[:space:]]*actions/checkout@' "$wf" \
       && grep -qE '(npm (ci|install|test|run)|yarn|pnpm|make|bash |sh |\./)' "$wf"; then
      finding "$base: SELF-HOSTED + PR CODE — the self-hosted job checks out and executes PR-controlled code."
      echo "  This is the direct path for a fork to drop a persistence implant."
      echo ""
    fi
  fi

  # ── Vector 3: persistence-writing step (only risky on self-hosted) ──
  # Scan non-comment lines only, so workflow comments do not trip the match.
  if [ "$selfhosted" -eq 1 ] \
     && grep -v '^[[:space:]]*#' "$wf" | grep -qE '(crontab|/etc/cron|systemctl --user|systemd/user|~/\.bashrc|~/\.profile|~/\.bash_profile|/etc/profile\.d|/etc/systemd|autostart)'; then
    finding "$base: PERSISTENCE-WRITING STEP — a step writes to a location that survives on a reused runner."
    echo "  crontab, shell profiles, user systemd units, and autostart entries"
    echo "  outlive the workspace and run in later jobs on the same machine."
    echo ""
    file_findings=1
  fi

  if [ "$file_findings" -eq 0 ]; then
    if [ "$selfhosted" -eq 1 ]; then
      ok "$base: self-hosted, but not on an untrusted trigger — confirm the runner is ephemeral."
    else
      ok "$base: runs on GitHub-hosted runners (ephemeral by design)."
    fi
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for runner persistence: $wf_dir ==="
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
  echo "=== Runtime scan for runner persistence: $repo ==="

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
  echo -e "${RED}=== RUNNER PERSISTENCE PATTERN DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration"
  echo "Fix: run untrusted code on ephemeral GitHub-hosted or single-use self-hosted runners."
  echo "     See hardened/07-runner-persistence/ in cicd-compromise-lab"
  exit 1
else
  ok "no runner persistence patterns detected."
  exit 0
fi
