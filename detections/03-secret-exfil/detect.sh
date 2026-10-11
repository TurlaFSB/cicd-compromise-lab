#!/usr/bin/env bash
# Detection script for scenario 03 — secret exfiltration
#
# Five detection vectors:
#   1. SECRETS IN LOGS:     secret values echoed, printed, or piped to stdout
#   2. MASKING BYPASS:      secrets transformed (base64, hex, substring) before output
#   3. OVERLY BROAD SCOPE:  secrets injected into jobs/steps that don't need them
#   4. BROAD PERMISSIONS:   write permissions granted at workflow level to all jobs
#   5. NO ENVIRONMENT GATE: deploy jobs accessing secrets without an environment
#                           protection rule (required reviewers)
#
# Two detection methods:
#   1. STATIC: scans workflow YAML files for the patterns above.
#   2. RUNTIME: queries the GitHub Actions API for workflow runs and checks
#      whether the workflow definition contains the vulnerable patterns.
#
# Requires: bash 4+, grep. Optional: gh CLI (for runtime mode).
# Usage:
#   ./detect.sh static  <path-to-repo>          # scan local workflows
#   ./detect.sh runtime <owner/repo> [--days N]  # query API (default: 7 days)
#
# Exit codes:
#   0 — no secret exfiltration pattern found
#   1 — secret exfiltration pattern DETECTED (findings printed to stdout)
#   2 — usage error or missing dependency

# shellcheck disable=SC2016  # regexes intentionally contain literal '$' (shell variable names in scanned YAML)
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

    local file_findings=0

    # ── Vector 1: secrets echoed or printed in run: steps ───────
    # Extract run: blocks and check for secret references in output commands
    local run_blocks
    run_blocks=$(awk '
      /^[[:space:]]+run:[[:space:]]*[|>]?[[:space:]]*$/ { in_run = 1; run_indent = 0; next }
      /^[[:space:]]+run:[[:space:]]+[^|>]/ { print $0; next }
      in_run && /^[[:space:]]*$/ { next }
      in_run && run_indent == 0 && /^[[:space:]]/ {
        match($0, /^[[:space:]]+/)
        run_indent = RLENGTH
        print $0
        next
      }
      in_run && run_indent > 0 {
        if (/^[[:space:]]/ && match($0, /^[[:space:]]+/) && RLENGTH >= run_indent) {
          print $0
        } else {
          in_run = 0
          run_indent = 0
        }
      }
    ' "$wf" 2>/dev/null || true)

    # Check for secrets printed directly
    if echo "$run_blocks" | grep -v '^[[:space:]]*#' | grep -qE '(echo|printf|cat|print)[[:space:]].*(\$DEPLOY_KEY|\$\{DEPLOY_KEY|\$\{\{[[:space:]]*secrets\.)'; then
      finding "$base: SECRET IN LOGS — secret value echoed or printed in a run: step."
      echo "  Matched line(s):"
      echo "$run_blocks" | grep -nE '(echo|printf|cat|print)[[:space:]].*(\$DEPLOY_KEY|\$\{DEPLOY_KEY|\$\{\{[[:space:]]*secrets\.)' | head -3 | sed 's/^/    /'
      echo ""
      file_findings=1
    fi

    # ── Vector 2: secret transformation (masking bypass) ────────
    if echo "$run_blocks" | grep -v '^[[:space:]]*#' | grep -qE '(\$DEPLOY_KEY|\$\{DEPLOY_KEY|\$\{\{[[:space:]]*secrets\.).*\|[[:space:]]*(base64|xxd|od|hexdump|rev|cut|openssl)'; then
      finding "$base: MASKING BYPASS — secret transformed before output (base64/hex/etc.)."
      echo "  GitHub's log masking only matches the EXACT registered value."
      echo "  Any transformation (base64, hex, substring) bypasses it completely."
      echo ""
      file_findings=1
    fi

    # ── Vector 3: secrets scoped to jobs that don't need them ───
    # Check for secrets in workflow-level or build-job-level env:
    # A secret should only be in the deploy job, not in build

    # Check workflow-level env: for secrets
    local wf_env
    wf_env=$(awk '
      /^env:/ { in_env = 1; next }
      in_env && /^[[:space:]]/ { print $0; next }
      in_env { in_env = 0 }
    ' "$wf" 2>/dev/null || true)

    if echo "$wf_env" | grep -qE 'secrets\.'; then
      finding "$base: BROAD SECRET SCOPE — secrets in workflow-level env: (available to ALL jobs)."
      echo "  Secrets should be scoped to the specific job and step that needs them."
      echo ""
      file_findings=1
    fi

    # Check for secrets in the build job's env: block
    local build_env
    build_env=$(awk '
      /^[[:space:]]+build:/ { in_build = 1; next }
      in_build && /^[[:space:]]+env:/ { in_env = 1; next }
      in_build && in_env && /^[[:space:]]{6,}/ { print $0; next }
      in_build && in_env && !/^[[:space:]]*$/ { in_env = 0 }
      in_build && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+build:/ { in_build = 0 }
    ' "$wf" 2>/dev/null || true)

    if echo "$build_env" | grep -qE 'secrets\.'; then
      finding "$base: BROAD SECRET SCOPE — secrets in build job env: (build should not need deploy credentials)."
      echo "  Matched secret(s):"
      echo "$build_env" | grep -E 'secrets\.' | sed 's/^/    /'
      echo ""
      file_findings=1
    fi

    # ── Vector 4: overly broad workflow-level permissions ────────
    # Check for write permissions at workflow level (not scoped per-job)
    local wf_perms
    wf_perms=$(awk '
      /^permissions:/ { in_perms = 1; next }
      in_perms && /^[[:space:]]/ { print $0; next }
      in_perms { in_perms = 0 }
    ' "$wf" 2>/dev/null || true)

    if echo "$wf_perms" | grep -qE '(contents|packages|actions|deployments|issues|pull-requests):[[:space:]]*write'; then
      finding "$base: BROAD PERMISSIONS — write permissions granted at workflow level (applies to ALL jobs)."
      echo "  Each job should declare only the permissions it needs."
      echo "  Matched permission(s):"
      echo "$wf_perms" | grep -E 'write' | sed 's/^/    /'
      echo ""
      file_findings=1
    fi

    # Single-line permissions: write-all
    if grep -v '^[[:space:]]*#' "$wf" | grep -qE '^permissions:[[:space:]]+write-all'; then
      finding "$base: BROAD PERMISSIONS — workflow uses 'permissions: write-all' (maximum privileges for all jobs)."
      echo ""
      file_findings=1
    fi

    # ── Vector 5: deploy without environment protection ──────────
    # If there's a deploy job with secrets but no environment: block
    local deploy_section
    deploy_section=$(awk '
      /^[[:space:]]+deploy:/ { in_deploy = 1; next }
      in_deploy && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+deploy:/ { in_deploy = 0 }
      in_deploy { print $0 }
    ' "$wf" 2>/dev/null || true)

    if [ -n "$deploy_section" ]; then
      local has_secrets_in_deploy=0
      if echo "$deploy_section" | grep -qE 'secrets\.'; then
        has_secrets_in_deploy=1
      fi

      local has_environment=0
      if echo "$deploy_section" | grep -qE '^[[:space:]]+environment:'; then
        has_environment=1
      fi

      if [ "$has_secrets_in_deploy" -eq 1 ] && [ "$has_environment" -eq 0 ]; then
        finding "$base: NO ENVIRONMENT GATE — deploy job uses secrets without an environment protection rule."
        echo "  Without required reviewers, any push to the trigger branch can"
        echo "  access deploy secrets automatically."
        echo ""
        file_findings=1
      fi
    fi

    # ── Vector 6: actions not pinned by SHA ──────────────────────
    if grep -v '^[[:space:]]*#' "$wf" | grep -qE 'uses:[[:space:]]+[^@]+@v[0-9]'; then
      local unpinned
      unpinned=$(grep -v '^[[:space:]]*#' "$wf" | grep -E 'uses:[[:space:]]+[^@]+@v[0-9]' | head -5)
      finding "$base: MUTABLE ACTION TAGS — actions referenced by tag instead of commit SHA."
      echo "  Unpinned action(s):"
      # shellcheck disable=SC2001  # multi-line indent; ${//} would only touch line 1
      echo "$unpinned" | sed 's/^/    /'
      echo ""
      file_findings=1
    fi

    if [ "$file_findings" -eq 0 ]; then
      ok "$base: no secret exfiltration patterns detected."
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

  # Fetch recent workflow runs
  local runs
  runs=$(gh api "repos/$repo/actions/runs?created=>$since&per_page=100" \
    --jq '.workflow_runs[] | "\(.id) \(.event) \(.conclusion) \(.workflow_id)"' 2>/dev/null || true)

  if [ -z "$runs" ]; then
    ok "no workflow runs found in the last $days days."
    return
  fi

  local run_count
  run_count=$(echo "$runs" | wc -l)
  echo "  Found $run_count workflow run(s). Checking workflow definitions..."

  # Track which workflows we've already analyzed
  local checked_workflows=""

  while IFS=' ' read -r run_id _event _conclusion workflow_id; do
    # Skip workflows we've already checked
    if echo "$checked_workflows" | grep -q "^${workflow_id}$"; then
      continue
    fi
    checked_workflows="${checked_workflows}
${workflow_id}"

    # Fetch the workflow file path
    local wf_path
    wf_path=$(gh api "repos/$repo/actions/workflows/$workflow_id" \
      --jq '.path' 2>/dev/null || true)

    if [ -z "$wf_path" ]; then
      warn "workflow $workflow_id: could not determine workflow path."
      continue
    fi

    # Fetch the workflow file content
    local wf_yaml
    wf_yaml=$(gh api "repos/$repo/contents/$wf_path" \
      --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

    if [ -z "$wf_yaml" ]; then
      warn "workflow $workflow_id: could not read workflow file $wf_path."
      continue
    fi

    echo ""
    echo "  --- Checking $wf_path (workflow $workflow_id) ---"

    # Check for secrets in echo/print statements
    if echo "$wf_yaml" | grep -v '^[[:space:]]*#' | grep -qE '(echo|printf)[[:space:]].*(\$\{?[A-Z_]*KEY|\$\{?[A-Z_]*SECRET|\$\{?[A-Z_]*TOKEN|\$\{\{[[:space:]]*secrets\.)'; then
      finding "workflow $wf_path: SECRET IN LOGS — secret reference found in echo/printf statement."
      echo "  Run: https://github.com/$repo/actions/runs/$run_id"
    fi

    # Check for base64/hex transformation of secrets
    if echo "$wf_yaml" | grep -v '^[[:space:]]*#' | grep -qE '\|[[:space:]]*(base64|xxd|od|hexdump)'; then
      if echo "$wf_yaml" | grep -v '^[[:space:]]*#' | grep -qE '(secrets\.|KEY|SECRET|TOKEN)'; then
        finding "workflow $wf_path: MASKING BYPASS — secret transformation (base64/hex) detected."
        echo "  Run: https://github.com/$repo/actions/runs/$run_id"
      fi
    fi

    # Check for workflow-level secret scoping
    local top_env
    top_env=$(echo "$wf_yaml" | awk '/^env:/{f=1;next} f && /^[[:space:]]/{print;next} f{f=0}')
    if echo "$top_env" | grep -qE 'secrets\.'; then
      finding "workflow $wf_path: BROAD SECRET SCOPE — secrets in workflow-level env: block."
      echo "  Run: https://github.com/$repo/actions/runs/$run_id"
    fi

    # Check for overly broad permissions
    local top_perms
    top_perms=$(echo "$wf_yaml" | awk '/^permissions:/{f=1;next} f && /^[[:space:]]/{print;next} f{f=0}')
    if echo "$top_perms" | grep -qE 'write'; then
      finding "workflow $wf_path: BROAD PERMISSIONS — write permissions at workflow level."
      echo "  Run: https://github.com/$repo/actions/runs/$run_id"
    fi

    # Check for unpinned actions
    if echo "$wf_yaml" | grep -v '^[[:space:]]*#' | grep -qE 'uses:[[:space:]]+[^@]+@v[0-9]'; then
      finding "workflow $wf_path: MUTABLE ACTION TAGS — actions not pinned by commit SHA."
      echo "  Run: https://github.com/$repo/actions/runs/$run_id"
    fi

  done <<< "$runs"
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
  echo -e "${RED}=== SECRET EXFILTRATION PATTERN DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene"
  echo "Fix: hardened/03-secret-exfil/deploy.yml in cicd-compromise-lab"
  exit 1
else
  echo ""
  ok "no secret exfiltration patterns detected."
  exit 0
fi
