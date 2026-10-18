#!/usr/bin/env bash
# Detection script for scenario 13 — credential leakage via artifacts
#
# Finds workflows that let a secret ride out of the pipeline inside an uploaded
# artifact, where anyone who can download the artifact gets the credential.
#
# Detection vectors:
#   1. PERSISTED CHECKOUT CREDENTIAL — actions/checkout without
#      persist-credentials: false, in a job that also uploads an artifact. The
#      token checkout writes into .git/config rides along if the upload sweeps
#      the working tree.
#   2. SECRET WRITTEN TO FILE — a run: step writes ${{ secrets.* }} into a file
#      (>, >>, tee). That file can then be uploaded, committed, or cached.
#   3. BROAD ARTIFACT PATH — actions/upload-artifact with a path of '.', the
#      workspace root, or '**', which captures dotfiles, .git/config, .env, and
#      other secret-bearing files.
#   4. HIDDEN FILES IN ARTIFACT — actions/upload-artifact with
#      include-hidden-files: true, re-enabling capture of .git, .env, .npmrc.
#
# Step structure is parsed by leak.awk so inputs are read in the right step.
# Requires: bash 4+, awk. Optional: gh CLI (runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAK_AWK="$SCRIPT_DIR/leak.awk"

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

is_broad_path() {
  # SC2016: the '$...' entries are literal YAML values to match, not expansions.
  # shellcheck disable=SC2016
  case "$1" in
    .|./|'*'|'**'|'**/*'|'${{ github.workspace }}'|'$GITHUB_WORKSPACE'|'${GITHUB_WORKSPACE}') return 0 ;;
    *) return 1 ;;
  esac
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  [ -f "$LEAK_AWK" ] || die "missing parser: $LEAK_AWK"

  local has_upload=0
  local -a checkouts=()      # "persist@line"
  local -a secret_files=()   # "line"
  local -a broad_paths=()    # "value@line"
  local -a hidden=()         # "line"

  local kind a b
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      UPLOAD)           has_upload=1 ;;
      CHECKOUT_PERSIST) checkouts+=("$b@$a") ;;
      SECRET_TO_FILE)   secret_files+=("$a") ;;
      UPLOAD_PATH)      if is_broad_path "$b"; then broad_paths+=("$b@$a"); fi ;;
      UPLOAD_HIDDEN)    hidden+=("$a") ;;
      *) : ;;
    esac
  done < <(awk -f "$LEAK_AWK" "$wf")

  # ── Vector 1: persisted checkout credential + an upload in the file ──
  if [ "$has_upload" -eq 1 ]; then
    local c persist ln
    for c in "${checkouts[@]+"${checkouts[@]}"}"; do
      persist="${c%@*}"; ln="${c##*@}"
      if [ "$persist" = "0" ]; then
        finding "$base:$ln: PERSISTED CHECKOUT CREDENTIAL — actions/checkout keeps credentials in .git/config (persist-credentials not set to false) in a job that uploads an artifact."
        echo "  Set persist-credentials: false, or the checkout token can leak inside the artifact."
        echo ""
        file_findings=1
      fi
    done
  fi

  # ── Vector 2: secret written to a file ──
  local s
  for s in "${secret_files[@]+"${secret_files[@]}"}"; do
    finding "$base:$s: SECRET WRITTEN TO FILE — a run step writes a secret to a file, which can be uploaded, cached, or committed."
    echo "  Pass the secret through env: to the tool that needs it; do not materialise it on disk."
    echo ""
    file_findings=1
  done

  # ── Vector 3: broad upload path ──
  local p val
  for p in "${broad_paths[@]+"${broad_paths[@]}"}"; do
    val="${p%@*}"; ln="${p##*@}"
    finding "$base:$ln: BROAD ARTIFACT PATH — upload-artifact path '$val' captures the whole tree (dotfiles, .git/config, .env)."
    echo "  Upload only the specific build output, e.g. path: dist/."
    echo ""
    file_findings=1
  done

  # ── Vector 4: hidden files in artifact ──
  local h
  for h in "${hidden[@]+"${hidden[@]}"}"; do
    finding "$base:$h: HIDDEN FILES IN ARTIFACT — include-hidden-files: true re-enables capture of .git, .env, .npmrc into the artifact."
    echo "  Remove it (the default excludes hidden files) and upload only the needed paths."
    echo ""
    file_findings=1
  done

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: no credential-leak-via-artifact pattern (narrow uploads, no persisted token, no secrets on disk)."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for credential leakage via artifacts: $wf_dir ==="
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
  echo "=== Runtime scan for credential leakage via artifacts: $repo ==="

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
  echo -e "${RED}=== CREDENTIAL LEAKAGE VIA ARTIFACTS DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene"
  echo "Fix: persist-credentials: false, pass secrets via env (never to disk), upload only the build output."
  echo "     See hardened/13-artifact-cred-leak/ in cicd-compromise-lab"
  exit 1
else
  ok "no credential leakage via artifacts detected."
  exit 0
fi
