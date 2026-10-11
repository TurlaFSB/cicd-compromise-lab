#!/usr/bin/env bash
# Detection script for scenario 05 — cache poisoning
#
# Finds GitHub Actions workflows where a build cache can be written by an
# untrusted trigger and later restored by a privileged one, letting a fork
# PR inject content into a trusted build or release.
#
# Detection vectors:
#   1. CACHE ON UNTRUSTED TRIGGER: a workflow triggered by pull_request (fork
#      PRs) or pull_request_target saves a cache (actions/cache, which writes
#      on cache miss) — the entry is attacker-influenced.
#   2. STATIC CACHE KEY: a cache key with no ${{ hashFiles(...) }} component,
#      so any run can populate the exact key a trusted build later restores.
#   3. BROAD RESTORE-KEYS: restore-keys with short/fuzzy prefixes that match
#      entries written under different keys (including attacker entries).
#   4. EXECUTABLE PATHS CACHED: caching build output or binary dirs (dist/,
#      build/, bin/, node_modules/.bin, .venv) rather than pure download
#      caches — poisoned entries become executable code in the build.
#
# One informational note (does not fail the scan):
#   CACHE IN PRIVILEGED JOB — a cache restore in a push/release/deployment
#   workflow. Safe on its own when the key is content-bound and no untrusted
#   workflow can write it; printed so a reviewer confirms that holds.
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
#   0 — no cache poisoning pattern found
#   1 — cache poisoning pattern DETECTED (findings printed to stdout)
#   2 — usage error or missing dependency

set -euo pipefail

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

# Does this workflow use actions/cache (the read-write action, not
# cache/restore which is read-only)?
uses_readwrite_cache() {
  grep -E 'uses:[[:space:]]*actions/cache@' "$1" | grep -vqE 'actions/cache/restore@'
}

# Triggers present in the workflow's `on:` block.
has_trigger() {
  # $1 = file, $2 = trigger token (e.g. pull_request, push, release)
  awk '
    /^on:/ { in_on = 1; next }
    in_on && /^[^[:space:]#]/ { in_on = 0 }
    in_on { print }
  ' "$1" | grep -qE "(^|[[:space:],])$2([[:space:],:]|$)"
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  # Only relevant if the workflow caches at all.
  if ! grep -qE 'uses:[[:space:]]*actions/cache' "$wf"; then
    ok "$base: no actions/cache usage."
    return
  fi

  local untrusted=0 privileged=0
  has_trigger "$wf" "pull_request"        && untrusted=1
  has_trigger "$wf" "pull_request_target" && untrusted=1
  has_trigger "$wf" "push"                && privileged=1
  has_trigger "$wf" "release"             && privileged=1

  # ── Vector 1: cache saved on an untrusted trigger ──
  if [ "$untrusted" -eq 1 ] && uses_readwrite_cache "$wf"; then
    finding "$base: CACHE ON UNTRUSTED TRIGGER — read-write actions/cache runs on pull_request(_target)."
    echo "  A fork PR controls what gets saved under the cache key."
    echo "  Use actions/cache/restore (read-only) on untrusted triggers, or isolate the key."
    echo ""
    file_findings=1
  fi

  # ── Informational: cache restore in a privileged workflow ──
  # Not a finding on its own — a push/release build caching downloads with a
  # content-bound key is normal. Printed so a reviewer confirms no sibling
  # workflow can write the key. Does not affect the exit code.
  local privileged_note=""
  if [ "$privileged" -eq 1 ] && [ "$untrusted" -eq 0 ]; then
    privileged_note="yes"
  fi

  # ── Vector 2: static cache key (no hashFiles) ──
  local keys
  keys=$(awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && /^[[:space:]]*key:[[:space:]]*[^[:space:]]/ {
      sub(/^[[:space:]]*key:[[:space:]]*/, ""); print; in_cache = 0
    }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0 }
  ' "$wf" || true)

  if [ -n "$keys" ]; then
    local k
    while IFS= read -r k; do
      [ -n "$k" ] || continue
      if ! printf '%s' "$k" | grep -q 'hashFiles('; then
        finding "$base: STATIC CACHE KEY — key '$k' has no hashFiles() component."
        echo "  Any run can populate this exact key. Bind it to a lockfile hash so"
        echo "  attacker content cannot occupy the key a trusted build restores."
        echo ""
        file_findings=1
      fi
    done <<< "$keys"
  fi

  # ── Vector 3: broad restore-keys ──
  if grep -qE '^[[:space:]]*restore-keys:' "$wf"; then
    finding "$base: BROAD RESTORE-KEYS — restore-keys fuzzy-match entries written under other keys."
    echo "  Prefix matching lets a near-miss attacker key satisfy a restore."
    echo "  Drop restore-keys on privileged builds, or make every prefix include a content hash."
    echo ""
    file_findings=1
  fi

  # ── Vector 4: executable/output paths cached ──
  local paths
  paths=$(awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && /^[[:space:]]*path:/ { in_path = 1; next }
    in_path && /^[[:space:]]+[^[:space:]#]/ { line = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line); print line; next }
    in_path && /^[[:space:]]*[a-z_-]+:/ { in_path = 0 }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0; in_path = 0 }
  ' "$wf" || true)

  if echo "$paths" | grep -qE '(^|/)(dist|build|out|bin|\.bin|\.venv|target|node_modules/\.bin)(/|$)'; then
    finding "$base: EXECUTABLE PATHS CACHED — build output / binary directories are cached."
    echo "  Matched path(s):"
    echo "$paths" | grep -E '(^|/)(dist|build|out|bin|\.bin|\.venv|target|node_modules/\.bin)(/|$)' | sed 's/^/    /'
    echo "  Poisoned entries here are executed as code. Cache only immutable downloads."
    echo ""
    file_findings=1
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: cache usage looks scoped (keyed to content, no untrusted write path)."
    if [ -n "$privileged_note" ]; then
      note "$base: restores a cache in a privileged (push/release) build — confirm no"
      echo "  pull_request(_target) workflow in this repo writes the same key."
    fi
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for cache poisoning: $wf_dir ==="
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
  echo "=== Runtime scan for cache poisoning: $repo ==="

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
  echo -e "${RED}=== CACHE POISONING PATTERN DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation"
  echo "Fix: isolate caches by trigger, key to content hashes, drop restore-keys on trusted builds."
  echo "     See hardened/05-cache-poisoning/ in cicd-compromise-lab"
  exit 1
else
  ok "no cache poisoning patterns detected."
  exit 0
fi
