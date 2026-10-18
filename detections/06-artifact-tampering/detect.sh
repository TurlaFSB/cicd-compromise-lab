#!/usr/bin/env bash
# Detection script for scenario 06 — artifact tampering
#
# Finds GitHub Actions workflows that move a build artifact from a producer
# to a publish/deploy step without any integrity binding, so a tampered
# artifact can be shipped.
#
# Detection vectors:
#   1. UNVERIFIED PUBLISH: a job downloads an artifact (actions/download-artifact
#      or gh run download) and then publishes/deploys (npm publish, gh release,
#      a registry push) with NO verification step in between (no attestation
#      verify, no cosign verify, no checksum check).
#   2. NO PROVENANCE: the workflow uploads an artifact (actions/upload-artifact)
#      but never attests, signs, or checksums it — there is nothing a consumer
#      could verify.
#   3. CROSS-WORKFLOW CONSUMPTION: a workflow_run-triggered workflow downloads
#      artifacts produced by another workflow run (classically an untrusted
#      producer), a prime tampering surface.
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
#   0 — no artifact tampering pattern found
#   1 — artifact tampering pattern DETECTED (findings printed to stdout)
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

# Patterns that indicate an artifact download (inter-job or cross-workflow).
downloads_artifact() {
  grep -qE 'uses:[[:space:]]*actions/download-artifact@' "$1" \
    || grep -qE 'gh[[:space:]]+run[[:space:]]+download' "$1" \
    || grep -qE 'uses:[[:space:]]*dawidd6/action-download-artifact@' "$1"
}

uploads_artifact() {
  grep -qE 'uses:[[:space:]]*actions/upload-artifact@' "$1"
}

# A publish / deploy / release action that ships bytes onward.
publishes() {
  grep -qE '(npm[[:space:]]+publish|yarn[[:space:]]+publish|pnpm[[:space:]]+publish|gh[[:space:]]+release[[:space:]]+(create|upload)|twine[[:space:]]+upload|docker[[:space:]]+push|softprops/action-gh-release@|pypa/gh-action-pypi-publish@)' "$1"
}

# Any integrity record created (producer side).
has_provenance() {
  grep -qE 'uses:[[:space:]]*actions/attest-build-provenance@' "$1" \
    || grep -qE 'uses:[[:space:]]*actions/attest@' "$1" \
    || grep -qE 'cosign[[:space:]]+sign' "$1" \
    || grep -qE 'sha256sum[^|]*>[[:space:]]*\S+' "$1"
}

# Any verification performed before publish (consumer side).
has_verification() {
  grep -qE 'gh[[:space:]]+attestation[[:space:]]+verify' "$1" \
    || grep -qE 'cosign[[:space:]]+verify' "$1" \
    || grep -qE 'slsa-framework/slsa-verifier' "$1" \
    || grep -qE 'sha256sum[[:space:]]+(-c|--check)' "$1"
}

# The workflow ships something: it publishes, or it runs on a release/tag
# trigger. Test and coverage artifacts in ordinary CI are not tamper targets,
# so the provenance vector only applies in this context.
release_context() {
  publishes "$1" && return 0
  awk '
    /^on:/ { in_on = 1; next }
    in_on && /^[^[:space:]#]/ { in_on = 0 }
    in_on { print }
  ' "$1" | grep -qE '(^|[[:space:]])(release|tags|tags-ignore)[[:space:]]*:'
}

triggered_by_workflow_run() {
  awk '
    /^on:/ { in_on = 1; next }
    in_on && /^[^[:space:]#]/ { in_on = 0 }
    in_on { print }
  ' "$1" | grep -qE '(^|[[:space:],])workflow_run([[:space:],:]|$)'
}

analyze_workflow() {
  local wf="$1" base="$2"
  local file_findings=0

  if ! downloads_artifact "$wf" && ! uploads_artifact "$wf"; then
    ok "$base: no artifact upload/download — not in scope for tampering."
    return
  fi

  # ── Vector 1: unverified publish ──
  if downloads_artifact "$wf" && publishes "$wf" && ! has_verification "$wf"; then
    finding "$base: UNVERIFIED PUBLISH — a downloaded artifact is published without integrity verification."
    echo "  Add attestation/signature verification (gh attestation verify, cosign verify)"
    echo "  or a checksum check between download and publish."
    echo ""
    file_findings=1
  fi

  # ── Vector 2: no provenance on upload ──
  if uploads_artifact "$wf" && release_context "$wf" && ! has_provenance "$wf"; then
    finding "$base: NO PROVENANCE — an artifact is uploaded with no attestation, signature, or checksum."
    echo "  A consumer has nothing to verify. Add actions/attest-build-provenance"
    echo "  in the build job (needs id-token: write, attestations: write)."
    echo ""
    file_findings=1
  fi

  # ── Vector 3: cross-workflow artifact consumption ──
  if triggered_by_workflow_run "$wf" && downloads_artifact "$wf"; then
    finding "$base: CROSS-WORKFLOW CONSUMPTION — a workflow_run job downloads artifacts from another run."
    echo "  The producing run may be untrusted (e.g. a fork). Verify provenance of"
    echo "  the artifact's origin before using it, and never publish it unverified."
    echo ""
    file_findings=1
  fi

  if [ "$file_findings" -eq 0 ]; then
    ok "$base: artifact flow has an integrity binding (attested and verified)."
  fi
}

detect_static() {
  local repo_path="${1:-.}"
  local wf_dir="$repo_path/.github/workflows"
  [ -d "$wf_dir" ] || die "no .github/workflows directory at $repo_path"

  echo "=== Static scan for artifact tampering: $wf_dir ==="
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
  echo "=== Runtime scan for artifact tampering: $repo ==="

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
  echo -e "${RED}=== ARTIFACT TAMPERING PATTERN DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation"
  echo "Fix: attest the artifact at build time and verify it before publishing."
  echo "     See hardened/06-artifact-tampering/ in cicd-compromise-lab"
  exit 1
else
  ok "no artifact tampering patterns detected."
  exit 0
fi
