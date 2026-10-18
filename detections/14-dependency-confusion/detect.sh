#!/usr/bin/env bash
# Detection script for scenario 14 — dependency confusion and install-script abuse
#
# The install phase is where supply-chain attacks land. This scanner checks the
# workflow and the npm config for the patterns that let a malicious or confused
# package run in CI.
#
# Detection vectors:
#   Workflow (.github/workflows):
#     1. PIPE TO SHELL — a remote script piped straight into a shell
#        (curl ... | sh, wget ... | bash): runs whatever the server serves.
#     2. INSTALL SCRIPTS ENABLED — an npm/yarn/pnpm install without
#        --ignore-scripts: dependency lifecycle scripts run at install time.
#     3. NO LOCKFILE INSTALL — `npm install` (not `npm ci`): versions are
#        resolved fresh, so a higher-versioned public package can be pulled in.
#   npm config (package.json + .npmrc):
#     4. UNPINNED SCOPE — a scoped dependency whose scope is not pinned to a
#        registry in .npmrc, so it resolves against the public registry
#        (dependency confusion). Parsed by npmcheck.py.
#
# Requires: bash 4+, grep, awk, python3 (for the npm-config half).
# Optional: gh CLI (runtime mode, workflow checks only).
# Usage:
#   ./detect.sh static  <path-to-repo>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NPMCHECK="$SCRIPT_DIR/npmcheck.py"

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
  local file_findings=0 ln line

  # Non-comment lines with their original numbers.
  # ── Vector 1: pipe a remote fetch into a shell ──
  while IFS=: read -r ln line; do
    finding "$base:$ln: PIPE TO SHELL — a remote script is piped into a shell; it runs whatever the server returns, unverified."
    echo "  Download to a file, verify a pinned checksum, then run it."
    echo ""
    file_findings=1
  done < <(grep -nE '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash)([[:space:]]|$)' "$wf" \
             | grep -vE '^[0-9]+:[[:space:]]*#' || true)

  # ── Vector 2 & 3: npm/yarn/pnpm install patterns ──
  while IFS=: read -r ln line; do
    # Vector 3: npm install (fresh resolution) rather than npm ci.
    if echo "$line" | grep -qE 'npm[[:space:]]+(install|i)([[:space:]]|$)'; then
      finding "$base:$ln: NO LOCKFILE INSTALL — 'npm install' resolves versions fresh; a higher-versioned public package can replace an internal one. Use 'npm ci'."
      echo ""
      file_findings=1
    fi
    # Vector 2: any install without --ignore-scripts runs lifecycle scripts.
    if ! echo "$line" | grep -qE -- '--ignore-scripts'; then
      finding "$base:$ln: INSTALL SCRIPTS ENABLED — dependency lifecycle scripts run during install; a malicious package executes code here. Add --ignore-scripts."
      echo ""
      file_findings=1
    fi
  done < <(grep -nE '(npm[[:space:]]+(install|i|ci)|yarn([[:space:]]+(install|add))?|pnpm[[:space:]]+(install|i|add))([[:space:]]|$)' "$wf" \
             | grep -vE '^[0-9]+:[[:space:]]*#' || true)

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: installs use a lockfile and --ignore-scripts, and nothing is piped from the network into a shell."
  fi
}

analyze_npm_config() {
  local pkg="$1" base="$2" npmrc="$3"
  check_deps python3
  local facts
  facts=$(python3 "$NPMCHECK" "$pkg" ${npmrc:+"$npmrc"} 2>/dev/null || true)
  local kind ln scope example cfg_findings=0
  while IFS=$'\t' read -r kind ln scope example; do
    [ "$kind" = "UNPINNED_SCOPE" ] || continue
    finding "$base:$ln: UNPINNED SCOPE — '$scope' (e.g. $example) is not pinned to a registry in .npmrc, so it resolves from the public registry (dependency confusion)."
    echo "  Add '$scope:registry=https://<internal-registry>' to .npmrc so the scope can only come from there."
    echo ""
    cfg_findings=1
  done <<< "$facts"
  [ "$cfg_findings" -eq 0 ] && ok "$base: scoped dependencies are pinned to a registry."
  return 0
}

detect_static() {
  local repo_path="${1:-.}"

  echo "=== Static scan for dependency confusion / install-script abuse: $repo_path ==="

  # Workflows.
  local wf_dir="$repo_path/.github/workflows" count_wf=0 wf
  if [ -d "$wf_dir" ]; then
    for wf in "$wf_dir"/*.yml "$wf_dir"/*.yaml; do
      [ -f "$wf" ] || continue
      count_wf=$((count_wf + 1))
      echo ""
      echo "--- $(basename "$wf") ---"
      analyze_workflow "$wf" "$(basename "$wf")"
    done
  fi
  [ "$count_wf" -gt 0 ] || warn "no workflow files found in $wf_dir"

  # npm manifests (shallow, so a repo scan does not sweep node_modules or
  # nested fixtures). Pair each with the nearest .npmrc (same dir, else root).
  local count_pkg=0 pkg dir npmrc
  while IFS= read -r pkg; do
    [ -f "$pkg" ] || continue
    count_pkg=$((count_pkg + 1))
    dir=$(dirname "$pkg")
    npmrc=""
    [ -f "$dir/.npmrc" ] && npmrc="$dir/.npmrc"
    [ -z "$npmrc" ] && [ -f "$repo_path/.npmrc" ] && npmrc="$repo_path/.npmrc"
    echo ""
    echo "--- ${pkg#"$repo_path"/} ---"
    analyze_npm_config "$pkg" "${pkg#"$repo_path"/}" "$npmrc"
  done < <(find "$repo_path" -maxdepth 2 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | sort)
}

detect_runtime() {
  local repo="$1"
  check_deps gh
  echo "=== Runtime scan for install-script abuse: $repo ==="
  echo "(runtime mode checks workflows only; npm config is read in static mode)"

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
    [ -d "$2" ] || die "not a directory: $2"
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
  echo -e "${RED}=== DEPENDENCY CONFUSION / INSTALL-SCRIPT ABUSE DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse"
  echo "Fix: npm ci --ignore-scripts, pin internal scopes to a private registry, never pipe the network into a shell."
  echo "     See hardened/14-dependency-confusion/ in cicd-compromise-lab"
  exit 1
else
  ok "no dependency confusion / install-script abuse detected."
  exit 0
fi
