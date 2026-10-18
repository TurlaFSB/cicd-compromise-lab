#!/usr/bin/env bash
# Detection script for scenario 11 — workflow_run artifact poisoning
#
# A `workflow_run` workflow runs in the BASE repository's context — its
# secrets, a read/write token, the default branch — even when the run that
# triggered it came from a fork pull request. The fork controls everything the
# upstream build produced (its artifacts, its branch name, its commit title),
# so a privileged `workflow_run` handler that consumes that material unsafely
# hands a fork-PR author code execution with the base repo's privileges.
#
# This scanner only looks at workflow_run-triggered workflows. For each one it
# reports:
#
# Detection vectors (findings):
#   1. UNTRUSTED WORKFLOW_RUN CONTEXT — an attacker-controllable
#      github.event.workflow_run field (head_branch, display_title,
#      head_repository, head_commit, ...) is interpolated into a run: shell
#      block. Classic template-expansion injection.
#   2. CHECKOUT OF WORKFLOW_RUN HEAD — actions/checkout pins `ref:` to the
#      triggering run's head branch/sha, building the fork's code in the
#      privileged context (pwn request via workflow_run).
#   3. POISONED ARTIFACT EXECUTED — the handler downloads the triggering run's
#      artifact (or the fork's checked-out tree) AND executes code from the
#      workspace (node/bash/npm/source ...). The bytes are attacker-controlled.
#
# Informational:
#   NOTE — the handler downloads an artifact from the triggering run. That is
#      legitimate, but the artifact is untrusted: treat it strictly as data,
#      validate it, and never execute it. (Not counted as a finding.)
#
# Permission/structure facts are extracted by scan.awk.
# Requires: bash 4+, awk. Optional: gh CLI (runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_AWK="$SCRIPT_DIR/scan.awk"

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 2; }
warn()    { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
ok()      { echo -e "${GREEN}OK:${NC} $*"; }
note()    { echo -e "${YELLOW}NOTE:${NC} $*"; }
finding() { echo -e "${RED}FINDING:${NC} $*"; FOUND=1; }

check_deps() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing dependency: $cmd"
  done
}

FOUND=0

# workflow_run fields a fork can set to arbitrary strings (injectable). The
# numeric/immutable fields (id, head_sha, run_number, conclusion, event,
# status) are not useful for shell injection and are excluded here.
is_injectable_field() {
  case "$1" in
    head_branch|display_title|head_repository|head_commit|name|path|head_ref) return 0 ;;
    *) return 1 ;;
  esac
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  [ -f "$SCAN_AWK" ] || die "missing parser: $SCAN_AWK"

  local onrun=0 dl_line=""
  local -a runctx=()        # "field@line"
  local -a checkout=()      # "field@line"
  local -a execs=()         # "line"

  local kind a b
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      ONRUN)        onrun=1 ;;
      RUNCTX)       runctx+=("$b@$a") ;;
      CHECKOUT_REF) checkout+=("$b@$a") ;;
      DL_RUNID|DL_GHSCRIPT) [ -z "$dl_line" ] && dl_line="$a" ;;
      EXEC)         execs+=("$a") ;;
      *) : ;;
    esac
  done < <(awk -f "$SCAN_AWK" "$wf")

  if [ "$onrun" -eq 0 ]; then
    ok "$base: not a workflow_run-triggered workflow — scenario 11 does not apply."
    return
  fi

  # ── Vector 1: untrusted workflow_run context in a run: block ──
  local c field ln shown=""
  for c in "${runctx[@]+"${runctx[@]}"}"; do
    field="${c%@*}"; ln="${c##*@}"
    if is_injectable_field "$field"; then
      finding "$base:$ln: UNTRUSTED WORKFLOW_RUN CONTEXT — github.event.workflow_run.$field is interpolated into a run: shell block."
      shown=1
    fi
  done
  if [ -n "$shown" ]; then
    echo "  A fork sets these fields. Pass them through env: and reference \"\$VAR\" in the script, never \${{ }}."
    echo ""
    file_findings=1
  fi

  # ── Vector 2: checkout of the triggering run's head ──
  local k
  for k in "${checkout[@]+"${checkout[@]}"}"; do
    field="${k%@*}"; ln="${k##*@}"
    finding "$base:$ln: CHECKOUT OF WORKFLOW_RUN HEAD — actions/checkout pins ref to github.event.workflow_run.$field (the fork's code)."
    echo "  This builds unreviewed fork code with the base repo's token and secrets. Do not check out the head here."
    echo ""
    file_findings=1
  done

  # ── Vector 3: poisoned artifact / checked-out code executed ──
  if [ -n "$dl_line" ] || [ "${#checkout[@]}" -gt 0 ]; then
    if [ "${#execs[@]}" -gt 0 ]; then
      finding "$base:${execs[0]}: POISONED ARTIFACT EXECUTED — code from the downloaded artifact / checked-out head is executed in the privileged context."
      echo "  The upstream run can be a fork PR, so these bytes are attacker-controlled. Never run them here."
      echo ""
      file_findings=1
    fi
  fi

  # ── Informational: artifact consumed from the triggering run ──
  if [ -n "$dl_line" ]; then
    note "$base:$dl_line: downloads an artifact from the triggering run. Treat it as untrusted data — validate it, never execute it."
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: workflow_run handler consumes upstream output safely (no untrusted context in run, no head checkout, no artifact execution)."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for workflow_run artifact poisoning: $wf_dir ==="
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
  echo "=== Runtime scan for workflow_run artifact poisoning: $repo ==="

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
  echo -e "${RED}=== WORKFLOW_RUN ARTIFACT POISONING DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution"
  echo "Fix: in a workflow_run handler, treat all upstream output as untrusted — no head checkout,"
  echo "     no executing downloaded artifacts, and pass workflow_run context through env: only."
  echo "     See hardened/11-workflow-run-poisoning/ in cicd-compromise-lab"
  exit 1
else
  ok "no workflow_run artifact poisoning detected."
  exit 0
fi
