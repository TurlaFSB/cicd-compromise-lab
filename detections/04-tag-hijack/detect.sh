#!/usr/bin/env bash
# Detection script for scenario 04 — mutable action tag hijack
#
# Detects GitHub Actions workflows that reference third-party actions by
# mutable tags (@v1, @v2, @main, @master, @latest, etc.) instead of
# pinned commit SHAs.
#
# A mutable tag can be force-pushed upstream at any time — by a malicious
# maintainer, a compromised account, or a supply-chain attacker — causing
# the consuming workflow to silently execute new, unreviewed code with
# full access to GITHUB_TOKEN and any secrets in scope.
#
# Detection vectors:
#   1. MUTABLE VERSION TAG:  uses: org/action@v1, @v2.3, @v4.1.0, etc.
#   2. MUTABLE BRANCH REF:  uses: org/action@main, @master, @develop, etc.
#   3. MUTABLE SPECIAL TAG:  uses: org/action@latest, @stable, @release, etc.
#   4. SHORT SHA:            uses: org/action@abc1234 (< 40 hex chars, not
#                            a full commit SHA — can collide or be retagged)
#   5. NO REF AT ALL:        uses: org/action (implicitly uses default branch)
#
# Exclusions (not flagged):
#   - Local actions:  uses: ./path/to/action (same repo, no tag to hijack)
#   - Docker actions: uses: docker://image:tag (separate supply chain)
#   - actions/* by GitHub: flagged by default; pass --skip-official to suppress
#
# Two detection methods:
#   1. STATIC:  scans workflow YAML files for the patterns above.
#   2. RUNTIME: queries the GitHub Actions API for workflow definitions.
#
# Requires: bash 4+, grep, awk.  Optional: gh CLI (for runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>  [--skip-official]
#   ./detect.sh runtime <owner/repo>    [--skip-official]
#
# Exit codes:
#   0 — no mutable tag references found (all actions pinned by SHA)
#   1 — mutable tag references DETECTED (findings printed to stdout)
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
SKIP_OFFICIAL=0

# ──────────────────────────────────────────────────────────────
# Core analysis: classify each `uses:` line
# ──────────────────────────────────────────────────────────────

# Analyze a single workflow file (path or piped content).
# Prints FINDING lines for any mutable references found.
analyze_workflow() {
  local wf_file="$1"
  local label="$2"
  local file_findings=0

  # Extract all non-comment `uses:` lines
  # First grep -n adds "lineno:" prefix; filter comments by checking after the prefix
  local uses_lines
  # Anchored to the YAML key: an unanchored match also hits 'statuses: read'.
  uses_lines=$(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]' "$wf_file" || true)

  if [ -z "$uses_lines" ]; then
    return
  fi

  while IFS= read -r line; do
    local lineno
    lineno=$(echo "$line" | cut -d: -f1)
    local uses_value
    uses_value=$(echo "$line" | sed -E 's/^[0-9]+:[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//' | sed 's/[[:space:]]*#.*//' | tr -d "'\"")

    # Skip local actions (./path)
    if [[ "$uses_value" == ./* ]] || [[ "$uses_value" == ../* ]]; then
      continue
    fi

    # Skip expression-built local paths (e.g. a workspace-relative action)
    if [[ "$uses_value" == \$* ]]; then
      continue
    fi

    # Skip docker:// references
    if [[ "$uses_value" == docker://* ]]; then
      continue
    fi

    # Extract org/action and ref parts
    local action_ref=""
    local action_name=""

    if [[ "$uses_value" == *"@"* ]]; then
      action_name="${uses_value%%@*}"
      action_ref="${uses_value##*@}"
    else
      action_name="$uses_value"
      action_ref=""
    fi

    # Skip official actions if --skip-official
    if [ "$SKIP_OFFICIAL" -eq 1 ]; then
      if [[ "$action_name" == actions/* ]] || [[ "$action_name" == github/* ]]; then
        continue
      fi
    fi

    # Classify the ref
    if [ -z "$action_ref" ]; then
      # Vector 5: no ref at all — uses default branch
      finding "$label:$lineno: NO REF — '$uses_value' has no @ref (uses default branch, always mutable)."
      file_findings=1

    elif [[ "$action_ref" =~ ^[0-9a-f]{40}$ ]]; then
      # Full 40-char hex SHA — this is correct, no finding
      continue

    elif [[ "$action_ref" =~ ^[0-9a-f]+$ ]] && [ "${#action_ref}" -lt 40 ]; then
      # Vector 4: short SHA — looks like a SHA but too short
      finding "$label:$lineno: SHORT SHA — '$uses_value' uses a ${#action_ref}-char ref (not a full 40-char SHA; may collide or be ambiguous)."
      file_findings=1

    elif [[ "$action_ref" =~ ^v[0-9] ]]; then
      # Vector 1: mutable version tag — @v1, @v2.3, @v4.1.0, etc.
      finding "$label:$lineno: MUTABLE TAG — '$uses_value' pinned by version tag (can be force-pushed upstream)."
      echo "  Fix: pin to the commit SHA behind $action_ref and note the tag in a comment."
      file_findings=1

    elif [[ "$action_ref" == "main" ]] || [[ "$action_ref" == "master" ]] || \
         [[ "$action_ref" == "develop" ]] || [[ "$action_ref" == "dev" ]] || \
         [[ "$action_ref" == "trunk" ]]; then
      # Vector 2: mutable branch ref
      finding "$label:$lineno: MUTABLE BRANCH — '$uses_value' tracks a branch (every upstream push changes what runs)."
      echo "  Fix: pin to a specific commit SHA."
      file_findings=1

    elif [[ "$action_ref" == "latest" ]] || [[ "$action_ref" == "stable" ]] || \
         [[ "$action_ref" == "release" ]] || [[ "$action_ref" == "nightly" ]]; then
      # Vector 3: mutable special tag
      finding "$label:$lineno: MUTABLE SPECIAL TAG — '$uses_value' uses a floating tag (semantically mutable by convention)."
      echo "  Fix: pin to a specific commit SHA."
      file_findings=1

    else
      # Any other non-SHA ref — could be a branch or an arbitrary tag
      # Check if it looks like a non-version tag or branch name
      if ! [[ "$action_ref" =~ ^[0-9a-f]{40}$ ]]; then
        finding "$label:$lineno: MUTABLE REF — '$uses_value' uses ref '$action_ref' (not a commit SHA; can be retagged)."
        echo "  Fix: pin to the commit SHA behind '$action_ref'."
        file_findings=1
      fi
    fi

  done <<< "$uses_lines"

  if [ "$file_findings" -eq 0 ]; then
    ok "$label: all actions pinned by full commit SHA."
  fi
}

# ──────────────────────────────────────────────────────────────
# Method 1: Static analysis of workflow YAML files
# ──────────────────────────────────────────────────────────────

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"

  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for mutable action tags: $wf_dir ==="

  local wf_count=0
  for wf in "$wf_dir"/*.yml "$wf_dir"/*.yaml; do
    [ -f "$wf" ] || continue
    wf_count=$((wf_count + 1))
    local base
    base=$(basename "$wf")
    echo ""
    echo "--- $base ---"
    analyze_workflow "$wf" "$base"
  done

  if [ "$wf_count" -eq 0 ]; then
    warn "no workflow files found in $wf_dir"
  fi
}

# ──────────────────────────────────────────────────────────────
# Method 2: Runtime detection via GitHub Actions API
# ──────────────────────────────────────────────────────────────

detect_runtime() {
  local repo="$1"

  check_deps gh

  echo "=== Runtime scan for mutable action tags: $repo ==="

  # List workflow files in the repository
  local wf_files
  wf_files=$(gh api "repos/$repo/contents/.github/workflows" \
    --jq '.[].name' 2>/dev/null || true)

  if [ -z "$wf_files" ]; then
    warn "no workflow files found in $repo/.github/workflows"
    return
  fi

  while IFS= read -r wf_name; do
    local wf_yaml
    wf_yaml=$(gh api "repos/$repo/contents/.github/workflows/$wf_name" \
      --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

    if [ -z "$wf_yaml" ]; then
      warn "could not read $wf_name from $repo"
      continue
    fi

    echo ""
    echo "--- $wf_name ---"

    # Write to a temp file for analyze_workflow
    local tmp_wf
    tmp_wf=$(mktemp)
    echo "$wf_yaml" > "$tmp_wf"
    analyze_workflow "$tmp_wf" "$wf_name"
    rm -f "$tmp_wf"

  done <<< "$wf_files"
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

# Parse trailing flags
args=()
for arg in "$@"; do
  case "$arg" in
    --skip-official) SKIP_OFFICIAL=1 ;;
    *) args+=("$arg") ;;
  esac
done
set -- "${args[@]}"

case "${1:-}" in
  static)
    [ -n "${2:-}" ] || die "usage: $0 static <path-to-repo> [--skip-official]"
    detect_static "$2"
    ;;
  runtime)
    [ -n "${2:-}" ] || die "usage: $0 runtime <owner/repo> [--skip-official]"
    detect_runtime "$2"
    ;;
  *)
    die "usage: $0 {static <path>|runtime <owner/repo>} [--skip-official]"
    ;;
esac

echo ""
if [ "$FOUND" -eq 1 ]; then
  echo -e "${RED}=== MUTABLE ACTION TAG REFERENCES DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse"
  echo "Fix: pin every action to a full commit SHA. Use Dependabot for automated update PRs."
  echo "     See hardened/04-tag-hijack/ci.yml in cicd-compromise-lab"
  exit 1
else
  ok "all actions pinned by full commit SHA — no mutable tag references found."
  exit 0
fi
