#!/usr/bin/env bash
# Detection script for scenario 10 — GITHUB_TOKEN over-privilege
#
# Finds workflows whose GITHUB_TOKEN holds more authority than any single job
# should: blanket `write-all`, no permissions block at all (falls back to the
# repository default), write scopes granted to every job at workflow level, and
# high-risk write scopes reachable from triggers that untrusted users can fire.
#
# Detection vectors:
#   1. WRITE-ALL: `permissions: write-all` at workflow or job level.
#   2. NO PERMISSIONS BLOCK: neither the workflow nor the job sets
#      `permissions:`, so the token takes the repository/organisation default
#      (often read-write on older repositories).
#   3. WORKFLOW-LEVEL WRITE: a write scope declared at workflow level applies
#      to every job, present and future. Declare write scopes per job.
#   4. WRITE ON UNTRUSTED TRIGGER: a high-risk write scope (contents, actions,
#      packages, id-token, deployments, pages, security-events, attestations)
#      or `write-all` is reachable from a trigger an outsider can fire
#      (pull_request_target, issue_comment, issues, workflow_run, ...).
#
# Permission facts are extracted by perms.awk (shared with the simulation).
# Requires: bash 4+, awk. Optional: gh CLI (runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMS_AWK="$SCRIPT_DIR/perms.awk"

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

is_high_risk() {
  case "$1" in
    contents|actions|packages|id-token|deployments|pages|security-events|attestations) return 0 ;;
    *) return 1 ;;
  esac
}

is_untrusted_trigger() {
  case "$1" in
    pull_request_target|issue_comment|issues|pull_request_review|pull_request_review_comment|workflow_run|discussion|discussion_comment|fork|watch) return 0 ;;
    *) return 1 ;;
  esac
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  [ -f "$PERMS_AWK" ] || die "missing parser: $PERMS_AWK"

  local wf_present=0 wf_scalar="" wf_scalar_ln=""
  local -a wf_writes=()          # "scope:level@line"
  local -a trigs=()
  local -a jobs=()
  local -A job_ln=() job_has=() job_scalar=() job_scalar_ln=()
  local -A job_writes=()         # job -> space-separated "scope@line"

  local kind a b c d
  while IFS=$'\t' read -r kind a b c d; do
    case "$kind" in
      TRIG)            trigs+=("$a") ;;
      WFPERM_PRESENT)  wf_present=1 ;;
      WFSCALAR)        wf_scalar="$b"; wf_scalar_ln="$a" ;;
      WFPERM)          [ "$c" = "write" ] && wf_writes+=("$b@$a") ;;
      JOB)             jobs+=("$a"); job_ln[$a]="$b" ;;
      JOBPERM_PRESENT) job_has[$a]=1 ;;
      JOBSCALAR)       job_scalar[$a]="$c"; job_scalar_ln[$a]="$b" ;;
      JOBPERM)         [ "$d" = "write" ] && job_writes[$a]+="$c@$b " ;;
      *) : ;;
    esac
  done < <(awk -f "$PERMS_AWK" "$wf")

  local untrusted=""
  local t
  for t in "${trigs[@]+"${trigs[@]}"}"; do
    if is_untrusted_trigger "$t"; then untrusted="${untrusted:+$untrusted, }$t"; fi
  done

  # ── Vector 1: write-all ──
  if [ "$wf_scalar" = "write-all" ]; then
    finding "$base:$wf_scalar_ln: WRITE-ALL — workflow-level 'permissions: write-all' grants every scope to every job."
    echo "  Replace with 'permissions: contents: read' and grant write scopes per job."
    echo ""
    file_findings=1
  fi
  local j
  for j in "${jobs[@]+"${jobs[@]}"}"; do
    if [ "${job_scalar[$j]:-}" = "write-all" ]; then
      finding "$base:${job_scalar_ln[$j]}: WRITE-ALL — job '$j' sets 'permissions: write-all'."
      echo "  Grant only the specific scopes this job uses."
      echo ""
      file_findings=1
    fi
  done

  # ── Vector 2: no permissions block ──
  if [ "$wf_present" -eq 0 ]; then
    for j in "${jobs[@]+"${jobs[@]}"}"; do
      if [ -z "${job_has[$j]:-}" ]; then
        finding "$base:${job_ln[$j]}: NO PERMISSIONS BLOCK — job '$j' sets no permissions and the workflow sets none."
        echo "  The token falls back to the repository default (often read-write). Add 'permissions: {}' or 'contents: read'."
        echo ""
        file_findings=1
      fi
    done
  fi

  # ── Vector 3: write scopes at workflow level ──
  if [ "${#wf_writes[@]}" -gt 0 ]; then
    local first="${wf_writes[0]}"
    finding "$base:${first##*@}: WORKFLOW-LEVEL WRITE — '${first%%@*}: write' is set at workflow level and applies to every job."
    echo "  Set the workflow floor to read and declare write scopes on the job that needs them."
    echo ""
    file_findings=1
  fi

  # ── Vector 4: high-risk write reachable from an untrusted trigger ──
  if [ -n "$untrusted" ]; then
    local g scope ln
    if [ "$wf_scalar" = "write-all" ]; then
      finding "$base:$wf_scalar_ln: WRITE ON UNTRUSTED TRIGGER — 'write-all' is reachable from untrusted trigger(s): $untrusted."
      echo "  An outsider can start this workflow; the token should hold the minimum."
      echo ""
      file_findings=1
    fi
    for g in "${wf_writes[@]+"${wf_writes[@]}"}"; do
      scope="${g%%@*}"; ln="${g##*@}"
      if is_high_risk "$scope"; then
        finding "$base:$ln: WRITE ON UNTRUSTED TRIGGER — '$scope: write' is reachable from untrusted trigger(s): $untrusted."
        echo ""
        file_findings=1
      fi
    done
    for j in "${jobs[@]+"${jobs[@]}"}"; do
      if [ "${job_scalar[$j]:-}" = "write-all" ]; then
        finding "$base:${job_scalar_ln[$j]}: WRITE ON UNTRUSTED TRIGGER — job '$j' has 'write-all' reachable from: $untrusted."
        echo ""
        file_findings=1
      fi
      for g in ${job_writes[$j]:-}; do
        scope="${g%%@*}"; ln="${g##*@}"
        if is_high_risk "$scope"; then
          finding "$base:$ln: WRITE ON UNTRUSTED TRIGGER — job '$j' holds '$scope: write', reachable from untrusted trigger(s): $untrusted."
          echo "  Drop it, or move the privileged step to a job that outsiders cannot trigger."
          echo ""
          file_findings=1
        fi
      done
    done
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: token permissions are scoped (explicit floor, narrow per-job grants)."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for GITHUB_TOKEN over-privilege: $wf_dir ==="
  local count=0 wf
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
  echo "=== Runtime scan for GITHUB_TOKEN over-privilege: $repo ==="

  local wf_files
  wf_files=$(gh api "repos/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null || true)
  [ -n "$wf_files" ] || { warn "no workflow files found in $repo"; return; }

  local wf_name wf_yaml tmp
  while IFS= read -r wf_name; do
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
  echo -e "${RED}=== GITHUB_TOKEN OVER-PRIVILEGE DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC"
  echo "Fix: set 'permissions: contents: read' (or {}) at workflow level; grant write scopes per job."
  echo "     See hardened/10-token-overprivilege/ in cicd-compromise-lab"
  exit 1
else
  ok "no GITHUB_TOKEN over-privilege detected."
  exit 0
fi
