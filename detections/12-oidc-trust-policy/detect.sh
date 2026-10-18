#!/usr/bin/env bash
# Detection script for scenario 12 — OIDC trust policy misconfiguration
#
# GitHub Actions OIDC lets a workflow exchange a short-lived, GitHub-signed
# token for real cloud credentials, with no long-lived secret stored. What a
# token may assume is decided by the cloud-side trust policy. This scanner
# checks BOTH halves of that exchange:
#
#   Cloud side (AWS IAM trust policy JSON):
#     1. WILDCARD SUBJECT — the sub condition admits more than one repo or any
#        ref (e.g. repo:org/*, a trailing :*, or a bare *).
#     2. NO SUBJECT CONDITION — the policy federates the GitHub OIDC provider
#        but sets no sub condition, so any repository on GitHub can assume it.
#     3. MISSING AUDIENCE CONDITION — no :aud condition, so the token's
#        audience is not constrained.
#
#   GitHub side (workflow YAML):
#     4. WORKFLOW-LEVEL ID-TOKEN — id-token: write at workflow level, so every
#        job can mint a cloud token. Grant it per job.
#     5. ID-TOKEN ON UNTRUSTED TRIGGER — id-token: write reachable from a
#        trigger an outsider can fire (pull_request_target, workflow_run, ...).
#
# Trust-policy facts are parsed by policy.py. Requires: bash 4+, awk, grep,
# python3. Optional: gh CLI (runtime mode, workflow checks only).
# Usage:
#   ./detect.sh static  <path-to-repo | path-to-trust-policy.json>
#   ./detect.sh runtime <owner/repo>
# Exit codes: 0 none, 1 detected, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_PY="$SCRIPT_DIR/policy.py"

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

UNTRUSTED_TRIGGERS='pull_request_target|issue_comment|issues|workflow_run|pull_request_review|pull_request_review_comment|discussion|discussion_comment|fork|watch'

# ── Cloud side: analyse one trust-policy JSON ────────────────────────
analyze_policy() {
  local pol="$1" base="$2"
  check_deps python3
  local facts
  facts=$(python3 "$POLICY_PY" "$pol" 2>/dev/null || true)
  [ -n "$facts" ] || return 0   # not a GitHub Actions trust policy

  local kind a b
  local pol_findings=0
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      WILDCARD_SUB)
        finding "$base:$a: WILDCARD SUBJECT — the OIDC sub condition '$b' admits more than one repository or any ref."
        echo "  Pin sub to one repo and ref, e.g. repo:org/repo:ref:refs/heads/main (or :environment:production)."
        echo ""
        pol_findings=1 ;;
      NO_SUB)
        finding "$base:$a: NO SUBJECT CONDITION — the policy federates the GitHub OIDC provider with no sub condition; any repository on GitHub can assume this role."
        echo "  Add a StringEquals condition on token.actions.githubusercontent.com:sub."
        echo ""
        pol_findings=1 ;;
      NO_AUD)
        finding "$base:$a: MISSING AUDIENCE CONDITION — no :aud condition, so the token audience is unconstrained."
        echo "  Add StringEquals token.actions.githubusercontent.com:aud = sts.amazonaws.com."
        echo ""
        pol_findings=1 ;;
      *) : ;;
    esac
  done <<< "$facts"

  if [ "$pol_findings" -eq 0 ]; then
    ok "$base: OIDC trust policy pins the audience and a specific subject."
  fi
}

# ── GitHub side: analyse one workflow YAML ───────────────────────────
analyze_workflow() {
  local wf="$1" base="$2"
  local wf_findings=0

  # id-token: write anywhere in the file (ignoring comment lines).
  local idtok_line
  idtok_line=$(grep -nE 'id-token:[[:space:]]*write' "$wf" \
    | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1 || true)

  if [ -z "$idtok_line" ]; then
    ok "$base: no id-token: write — workflow cannot mint an OIDC token."
    return
  fi

  # Workflow-level permissions block: lines from a column-0 `permissions:` to
  # the next column-0 key. If id-token: write appears there, it is workflow-wide.
  local wf_perm_idtok_line
  wf_perm_idtok_line=$(awk '
    /^permissions:[[:space:]]*$/ {inblk=1; next}
    inblk && /^[^[:space:]]/ {inblk=0}
    inblk && /id-token:[[:space:]]*write/ {print NR; exit}
  ' "$wf" || true)

  if [ -n "$wf_perm_idtok_line" ]; then
    finding "$base:$wf_perm_idtok_line: WORKFLOW-LEVEL ID-TOKEN — id-token: write is granted at workflow level, so every job can mint a cloud token."
    echo "  Move id-token: write onto the single job that assumes the cloud role."
    echo ""
    wf_findings=1
  fi

  # Untrusted trigger reachable with id-token. Scan only the on: block, skip
  # comment lines, and take the trigger name from the matched line itself.
  local trig
  trig=$(awk -v re="$UNTRUSTED_TRIGGERS" '
    /^[[:space:]]*#/ {next}
    /^on:[[:space:]]*$/ {inon=1; next}
    /^on:/ {inon=1}
    inon && /^[^[:space:]]/ && $0 !~ /^on:/ {inon=0}
    (inon || $0 ~ /^on:/) && match($0, "(^|[^a-zA-Z_])(" re ")([^a-zA-Z_]|$)") {
      if (match($0, "(" re ")")) { print NR "\t" substr($0, RSTART, RLENGTH); exit }
    }
  ' "$wf" || true)

  if [ -n "$trig" ]; then
    local trig_line t
    trig_line="${trig%%$'\t'*}"; t="${trig#*$'\t'}"
    finding "$base:$trig_line: ID-TOKEN ON UNTRUSTED TRIGGER — id-token: write is reachable from '$t', a trigger an outsider can fire."
    echo "  An injected or fork-controlled step could mint an OIDC token. Use a trusted trigger (push to a protected branch, tag, or a protected environment)."
    echo ""
    wf_findings=1
  fi

  if [ "$wf_findings" -eq 0 ]; then
    ok "$base: id-token: write is scoped to a job and reached only from trusted triggers."
  fi
}

# ── Discovery ────────────────────────────────────────────────────────
is_trust_policy_file() {
  grep -q 'token\.actions\.githubusercontent\.com' "$1" 2>/dev/null \
    && grep -qi 'sts:AssumeRoleWithWebIdentity' "$1" 2>/dev/null
}

detect_static() {
  local target="$1"

  # A direct path to a single JSON policy.
  if [ -f "$target" ] && [[ "$target" == *.json ]]; then
    echo "=== Static scan of OIDC trust policy: $target ==="
    echo ""
    echo "--- $(basename "$target") ---"
    analyze_policy "$target" "$(basename "$target")"
    return
  fi

  [ -d "$target" ] || die "not a directory or .json file: $target"

  echo "=== Static scan for OIDC trust policy misconfiguration: $target ==="

  # Cloud side: trust policies in conventional locations (shallow, so a repo
  # scan does not sweep unrelated JSON fixtures). Point the scanner at a file
  # directly to check a policy kept elsewhere.
  local count_pol=0 f
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    is_trust_policy_file "$f" || continue
    count_pol=$((count_pol + 1))
    echo ""
    echo "--- ${f#"$target"/} ---"
    analyze_policy "$f" "${f#"$target"/}"
  done < <(find "$target" -maxdepth 2 -name '*.json' 2>/dev/null | sort)
  if [ "$count_pol" -eq 0 ]; then
    warn "no OIDC trust policy found near $target (looked ≤2 levels deep); pass a policy file path directly to scan one elsewhere."
  fi

  # GitHub side: workflows.
  local wf_dir="$target/.github/workflows" count_wf=0 wf
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
}

detect_runtime() {
  local repo="$1"
  check_deps gh
  echo "=== Runtime scan for OIDC id-token exposure: $repo ==="
  echo "(runtime mode checks workflows only; cloud trust policies are not in the repo)"

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
    [ -n "${2:-}" ] || die "usage: $0 static <path-to-repo | trust-policy.json>"
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
  echo -e "${RED}=== OIDC TRUST POLICY MISCONFIGURATION DETECTED ===${NC}"
  echo "See: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC"
  echo "Fix: pin the trust policy's :aud and :sub to one repo and ref; grant id-token: write per job on trusted triggers."
  echo "     See hardened/12-oidc-trust-policy/ in cicd-compromise-lab"
  exit 1
else
  ok "no OIDC trust policy misconfiguration detected."
  exit 0
fi
