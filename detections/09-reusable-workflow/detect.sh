#!/usr/bin/env bash
# Detection script for scenario 09 — reusable workflow trust boundary
#
# Finds callers that invoke a reusable workflow unsafely: by a mutable ref
# (so upstream can change what runs), or with `secrets: inherit` (handing the
# callee every secret the caller holds), especially across an org boundary.
#
# A reusable workflow is invoked with a JOB-LEVEL `uses:` (not a step-level
# `- uses:`), pointing at a `.github/workflows/*.yml` file.
#
# Detection vectors:
#   1. REUSABLE BY MUTABLE REF: a job-level `uses:` reusable workflow pinned
#      to a tag/branch (@main, @v1, @release) instead of a full commit SHA.
#   2. SECRETS INHERIT: a reusable-workflow call passes `secrets: inherit`,
#      giving the callee ALL of the caller's secrets.
#   3. EXTERNAL + INHERIT: the reusable workflow lives in a different
#      owner/repo AND receives `secrets: inherit` — all secrets cross an
#      external trust boundary.
#
# Two detection methods: static (local YAML) and runtime (GitHub API).
# Requires: bash 4+, grep, awk. Optional: gh CLI (runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

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

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  # Job-level reusable-workflow calls: a `uses:` line that is NOT a step list
  # item (no leading dash) and references a workflow file or owner/repo ref.
  local reusable
  reusable=$(grep -nE '^[[:space:]]+uses:[[:space:]]' "$wf" \
             | grep -vE '^[0-9]+:[[:space:]]*-' \
             | grep -vE '^[0-9]+:[[:space:]]*#' || true)

  if [ -z "$reusable" ]; then
    ok "$base: no reusable-workflow calls."
    return
  fi

  local has_inherit=0
  grep -v '^[[:space:]]*#' "$wf" | grep -qE '^[[:space:]]*secrets:[[:space:]]*inherit[[:space:]]*$' && has_inherit=1

  local line lineno value
  while IFS= read -r line; do
    lineno=$(echo "$line" | cut -d: -f1)
    value=$(echo "$line" | sed 's/^[0-9]*:[[:space:]]*uses:[[:space:]]*//' | sed 's/[[:space:]]*#.*//' | tr -d "'\"")

    # Local reusable workflow (same repo) — trusted, no ref to hijack.
    if [[ "$value" == ./* ]]; then
      continue
    fi

    local ref="${value##*@}"
    local path="${value%@*}"

    # ── Vector 1: mutable ref ──
    if [[ "$value" == *"@"* ]] && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
      finding "$base:$lineno: REUSABLE BY MUTABLE REF — '$value' pinned to '$ref', not a commit SHA."
      echo "  Upstream can change what this workflow runs. Pin to a full commit SHA."
      echo ""
      file_findings=1
    fi

    # ── Vector 3: external + secrets: inherit ──
    # owner/repo is the first two path segments; compare against this repo if known.
    if [ "$has_inherit" -eq 1 ]; then
      finding "$base:$lineno: EXTERNAL + INHERIT — reusable workflow '$path' receives 'secrets: inherit'."
      echo "  The callee gets EVERY caller secret. Pass only the needed secrets by name."
      echo ""
      file_findings=1
    fi
  done <<< "$reusable"

  # ── Vector 2: secrets: inherit anywhere (even if ref were pinned) ──
  if [ "$has_inherit" -eq 1 ] && [ "$file_findings" -eq 0 ]; then
    finding "$base: SECRETS INHERIT — a reusable-workflow call uses 'secrets: inherit'."
    echo "  Pass only the secrets the callee needs, explicitly by name."
    echo ""
    file_findings=1
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: reusable workflows are SHA-pinned and pass secrets explicitly."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for reusable-workflow trust issues: $wf_dir ==="
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
  echo "=== Runtime scan for reusable-workflow trust issues: $repo ==="

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
  echo -e "${RED}=== REUSABLE WORKFLOW TRUST ISSUE DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse"
  echo "Fix: pin reusable workflows by commit SHA and pass only needed secrets by name."
  echo "     See hardened/09-reusable-workflow/ in cicd-compromise-lab"
  exit 1
else
  ok "no reusable-workflow trust issues detected."
  exit 0
fi
