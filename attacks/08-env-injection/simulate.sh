#!/usr/bin/env bash
# simulate.sh — show how untrusted text written to $GITHUB_ENV smuggles an
# extra environment variable into later steps, and judge a workflow for it.
#
# Two parts:
#   1. MECHANISM (always runs): take an attacker-controlled "issue title"
#      (payload/inject.txt: a benign first line plus an injected
#      NODE_OPTIONS line) and append it to a fake GITHUB_ENV file the
#      vulnerable way (`echo "ISSUE_TITLE=<untrusted>" >> env`). Parse the
#      file as the runner does and show NODE_OPTIONS is now set — an
#      injected variable the author never wrote. Then do it the safe way
#      (value held in a shell variable, never written to the env file) and
#      show no extra variable appears.
#   2. VERDICT: inspect a workflow — does a run: step write untrusted context
#      (${{ github.event.* }} etc.) to $GITHUB_ENV or $GITHUB_PATH? Reports
#      INJECTABLE or SAFE.
#
# Usage:
#   ./simulate.sh                 # judge the vulnerable triage.yml (default)
#   ./simulate.sh <workflow.yml>  # judge a specific workflow
#
# Exit codes:
#   0 — no untrusted writes to GITHUB_ENV/GITHUB_PATH (safe)
#   1 — untrusted data reaches GITHUB_ENV/GITHUB_PATH (injectable)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="${1:-$SCRIPT_DIR/triage.yml}"
PAYLOAD="$SCRIPT_DIR/payload/inject.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WF" ] || { echo "no workflow at $WF" >&2; exit 2; }
[ -f "$PAYLOAD" ] || { echo "no payload at $PAYLOAD" >&2; exit 2; }

# Parse a GITHUB_ENV-style file into "KEY present" checks (first line of each
# KEY=VALUE, as the runner interprets single-line entries).
injected_var() {
  grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$1" | tr -d '=' | sort -u
}

echo -e "${BOLD}=== Part 1: GITHUB_ENV injection mechanism (concrete) ===${NC}"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
title=$(cat "$PAYLOAD")   # attacker-controlled multi-line "issue title"

# Vulnerable: untrusted title written straight into the env file.
vuln_env="$work/vuln_env"
printf 'ISSUE_TITLE=%s\n' "$title" >> "$vuln_env"
echo "vulnerable write produced these variables:"
injected_var "$vuln_env" | sed 's/^/    /'
if injected_var "$vuln_env" | grep -q '^NODE_OPTIONS$'; then
  echo -e "  ${RED}NODE_OPTIONS was injected${NC} — it would alter the next \`node\` step."
fi
echo ""

# Safe: value kept in a shell variable, never written to the env file.
safe_env="$work/safe_env"
: > "$safe_env"   # the hardened workflow passes the title via env:, not GITHUB_ENV
echo "safe handling wrote nothing untrusted to the env file:"
if [ -s "$safe_env" ] && injected_var "$safe_env" | grep -q .; then
  echo "    (unexpected variables present)"
else
  echo -e "    ${GREEN}no injected variables${NC}"
fi
echo ""

echo -e "${BOLD}=== Part 2: verdict for $(basename "$WF") ===${NC}"

# Untrusted-context tokens (same set scenario 02 treats as attacker-controlled).
untrusted_re='github\.event\.(issue|pull_request|comment|review|discussion|head_commit)|github\.head_ref'

writes_untrusted=0
if grep -v '^[[:space:]]*#' "$WF" \
   | grep -E '>>[[:space:]]*"?\$\{?GITHUB_(ENV|PATH)\}?"?' \
   | grep -qE "$untrusted_re"; then
  writes_untrusted=1
fi
# Also catch the common two-line form: an untrusted echo piped on one line.
if grep -v '^[[:space:]]*#' "$WF" \
   | grep -qE 'echo[[:space:]]+"?[^"]*\$\{\{[[:space:]]*(github\.event|github\.head_ref)[^}]*\}\}[^"]*"?[[:space:]]*>>[[:space:]]*"?\$\{?GITHUB_(ENV|PATH)'; then
  writes_untrusted=1
fi

echo "untrusted context written to \$GITHUB_ENV / \$GITHUB_PATH: $([ $writes_untrusted -eq 1 ] && echo yes || echo no)"
echo ""

if [ "$writes_untrusted" -eq 1 ]; then
  echo -e "${RED}INJECTABLE:${NC} attacker-controlled text reaches the runner environment files."
  echo "  A crafted value can inject an extra variable (NODE_OPTIONS, LD_PRELOAD)"
  echo "  or a PATH entry that hijacks a later step. Pass untrusted data through"
  echo "  step-scoped env: instead, and never echo it into GITHUB_ENV/GITHUB_PATH."
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} no untrusted data is written to GITHUB_ENV or GITHUB_PATH."
exit 0
