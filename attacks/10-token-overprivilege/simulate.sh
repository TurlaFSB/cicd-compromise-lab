#!/usr/bin/env bash
# simulate.sh — compute the GITHUB_TOKEN a compromised step would hold, and
# what an attacker could do with it.
#
# For every job in a workflow this resolves the EFFECTIVE token permissions
# the way GitHub does (job `permissions:` > workflow `permissions:` >
# repository default), then maps each write scope to the concrete actions it
# unlocks. It reports a verdict per workflow.
#
# Verdict rule — OVER-PRIVILEGED when a job's effective token holds a
# high-risk write scope AND that authority is either
#   (a) inherited rather than declared on the job (write-all, workflow-level
#       write, or the repository default), or
#   (b) reachable from a trigger an untrusted user can fire.
# A write scope declared on the job itself, on a maintainer-only trigger, is
# a deliberate grant and is reported but not condemned.
#
# The repository default is assumed PERMISSIVE (read-write), as on older
# repositories and many organisations; new repositories default to
# restricted, which is why setting permissions explicitly matters.
#
# Usage:
#   ./simulate.sh [workflow.yml ...]   # default: every *.yml next to this script
# Exit codes: 0 safe, 1 over-privileged, 2 usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMS_AWK="$SCRIPT_DIR/../../detections/10-token-overprivilege/perms.awk"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$PERMS_AWK" ] || { echo "missing parser: $PERMS_AWK" >&2; exit 2; }

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=("$SCRIPT_DIR"/*.yml)
fi

ALL_SCOPES="actions attestations checks contents deployments discussions id-token issues packages pages pull-requests security-events statuses"
HIGH_RISK="contents actions packages id-token deployments pages security-events attestations"
# Permissive repository default (what a job with no permissions block gets).
DEFAULT_WRITE="actions checks contents deployments discussions issues packages pages pull-requests statuses"

impact() {
  case "$1" in
    contents)        echo "push commits and tags to unprotected branches; create or overwrite releases" ;;
    actions)         echo "delete Actions caches and artifacts (enables cache poisoning); cancel or re-run workflows" ;;
    packages)        echo "publish or overwrite packages in the registry" ;;
    id-token)        echo "mint OIDC tokens and assume any cloud role whose trust policy allows this repo" ;;
    deployments)     echo "create deployments and mark them successful" ;;
    pages)           echo "publish arbitrary content to GitHub Pages" ;;
    security-events) echo "upload or dismiss code-scanning alerts" ;;
    attestations)    echo "sign provenance attestations as this repository" ;;
    pull-requests)   echo "comment on, label, and (if allowed) approve pull requests" ;;
    issues)          echo "edit, close, and comment on issues" ;;
    checks|statuses) echo "forge passing checks and commit statuses" ;;
    discussions)     echo "edit and delete discussions" ;;
    *)               echo "write access to $1" ;;
  esac
}

contains() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
is_untrusted() {
  case "$1" in
    pull_request_target|issue_comment|issues|pull_request_review|pull_request_review_comment|workflow_run|discussion|discussion_comment|fork|watch) return 0 ;;
    *) return 1 ;;
  esac
}

OVERALL=0

judge_file() {
  local wf="$1"
  local wf_present=0 wf_scalar="" wf_write=""
  local -a jobs=() trigs=()
  local -A job_has=() job_scalar=() job_write=()
  local kind a b c d

  while IFS=$'\t' read -r kind a b c d; do
    case "$kind" in
      TRIG)            trigs+=("$a") ;;
      WFPERM_PRESENT)  wf_present=1 ;;
      WFSCALAR)        wf_scalar="$b" ;;
      WFPERM)          [ "$c" = "write" ] && wf_write+="$b " ;;
      JOB)             jobs+=("$a") ;;
      JOBPERM_PRESENT) job_has[$a]=1 ;;
      JOBSCALAR)       job_scalar[$a]="$c" ;;
      JOBPERM)         [ "$d" = "write" ] && job_write[$a]+="$c " ;;
      *) : ;;
    esac
  done < <(awk -f "$PERMS_AWK" "$wf")

  local untrusted="" t
  for t in "${trigs[@]+"${trigs[@]}"}"; do
    if is_untrusted "$t"; then untrusted="${untrusted:+$untrusted, }$t"; fi
  done

  echo -e "${BOLD}=== $(basename "$wf") ===${NC}"
  echo "  triggers: ${trigs[*]:-(none parsed)}${untrusted:+   [untrusted: $untrusted]}"

  local wf_bad=0 j
  for j in "${jobs[@]+"${jobs[@]}"}"; do
    local source writes="" inherited=0
    if [ -n "${job_scalar[$j]:-}" ]; then
      source="job-level 'permissions: ${job_scalar[$j]}'"
      if [ "${job_scalar[$j]}" = "write-all" ]; then writes="$ALL_SCOPES"; fi
    elif [ -n "${job_has[$j]:-}" ]; then
      source="job-level permissions block"
      writes="${job_write[$j]:-}"
    elif [ "$wf_present" -eq 1 ]; then
      inherited=1
      if [ -n "$wf_scalar" ]; then
        source="inherited from workflow-level 'permissions: $wf_scalar'"
        if [ "$wf_scalar" = "write-all" ]; then writes="$ALL_SCOPES"; fi
      else
        source="inherited from workflow-level permissions block"
        writes="$wf_write"
      fi
    else
      inherited=1
      source="repository default (no permissions block anywhere) — assumed permissive"
      writes="$DEFAULT_WRITE"
    fi

    echo "  job '$j' — token source: $source"
    local high="" s
    if [ -z "$writes" ]; then
      echo "      effective write scopes: none"
    else
      for s in $writes; do
        echo "      write: $s  →  $(impact "$s")"
        if contains "$s" "$HIGH_RISK"; then high="$high $s"; fi
      done
    fi

    local reach=""
    [ -n "$untrusted" ] && reach="reachable from untrusted triggers"
    if [ "$inherited" -eq 1 ]; then reach="${reach:+$reach and }inherited, not declared on the job"; fi
    if [ "${job_scalar[$j]:-}" = "write-all" ]; then reach="${reach:+$reach and }granted by a blanket write-all"; fi
    if [ -n "$high" ] && [ -n "$reach" ]; then
      high="${high# }"
      echo -e "      ${RED}OVER-PRIVILEGED${NC} — high-risk write (${high// /,}) is $reach"
      wf_bad=1
    elif [ -n "$high" ]; then
      echo -e "      ${YELLOW}deliberate grant${NC} — declared on the job, maintainer-only trigger."
    fi
  done

  if [ "$wf_bad" -eq 1 ]; then
    echo -e "  verdict: ${RED}OVER-PRIVILEGED${NC} — a compromised step here holds far more than it needs."
    OVERALL=1
  else
    echo -e "  verdict: ${GREEN}SAFE${NC} — token is scoped to what each job needs."
  fi
  echo ""
}

for f in "${files[@]}"; do
  [ -f "$f" ] || { echo "no such workflow: $f" >&2; exit 2; }
  judge_file "$f"
done

if [ "$OVERALL" -eq 1 ]; then
  echo -e "${RED}RESULT: over-privileged GITHUB_TOKEN${NC}"
  exit 1
fi
echo -e "${GREEN}RESULT: GITHUB_TOKEN scoped${NC}"
exit 0
