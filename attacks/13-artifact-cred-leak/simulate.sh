#!/usr/bin/env bash
# simulate.sh — demonstrate credential leakage through an artifact offline, then
# judge a workflow for the leak.
#
#   Part 1 (MECHANISM, always runs): build a fake workspace holding a token in
#     .git/config and a token in .npmrc, plus a clean dist/. Archive it two
#     ways — the whole tree (what `path: .` + include-hidden-files uploads) and
#     dist/ only (the hardened upload) — and grep each archive for the secret.
#     The broad archive LEAKS; the narrow one is SAFE.
#
#   Part 2 (VERDICT): inspect a workflow for the four leak patterns and report
#     LEAKY (exit 1) or SAFE (exit 0).
#
# Usage:
#   ./simulate.sh                 # judge the vulnerable release.yml
#   ./simulate.sh <workflow.yml>  # judge a specific workflow
#
# Exit codes: 0 safe, 1 leaky, 2 usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="${1:-$SCRIPT_DIR/release.yml}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WF" ] || { echo "no workflow at $WF" >&2; exit 2; }

echo -e "${BOLD}=== Part 1: does the archived artifact contain the secret? ===${NC}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ws="$work/workspace"
mkdir -p "$ws/.git" "$ws/dist"
TOKEN="ghs_DUMMYtoken1234567890abcdefLEAK"
NPM="npm_DUMMYtoken0987654321zyxwLEAK"
# The checkout token persisted into .git/config, and the npm token on disk.
printf '[http "https://github.com/"]\n  extraheader = AUTHORIZATION: basic %s\n' "$TOKEN" > "$ws/.git/config"
printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM" > "$ws/.npmrc"
printf 'export const x = 1;\n' > "$ws/dist/app.js"

# Broad upload: whole tree, hidden files included.
broad="$work/broad.tar"; ( cd "$ws" && tar -cf "$broad" . ) 2>/dev/null
# Narrow upload: dist/ only.
narrow="$work/narrow.tar"; ( cd "$ws" && tar -cf "$narrow" dist ) 2>/dev/null

if tar -xOf "$broad" 2>/dev/null | grep -qE "$TOKEN|$NPM"; then
  echo -e "  broad upload (path: . , hidden files): ${RED}secret present in artifact → LEAKED${NC}"
fi
if tar -xOf "$narrow" 2>/dev/null | grep -qE "$TOKEN|$NPM"; then
  echo -e "  narrow upload (path: dist/):           ${RED}secret present → LEAKED${NC}"
else
  echo -e "  narrow upload (path: dist/):           ${GREEN}no secret in artifact → SAFE${NC}"
fi
echo ""

echo -e "${BOLD}=== Part 2: verdict for $(basename "$WF") ===${NC}"
body=$(grep -vE '^[[:space:]]*#' "$WF")

uploads=0
if printf '%s\n' "$body" | grep -qE 'uses:[[:space:]]*actions/upload-artifact'; then uploads=1; fi

reasons=()

# Persisted checkout credential alongside an upload.
if [ "$uploads" -eq 1 ] \
   && printf '%s\n' "$body" | grep -qE 'uses:[[:space:]]*actions/checkout' \
   && ! printf '%s\n' "$body" | grep -qE 'persist-credentials:[[:space:]]*false'; then
  reasons+=("checkout keeps its token in .git/config and the job uploads an artifact")
fi
# Secret written to a file.
if printf '%s\n' "$body" | grep -E '\$\{\{[[:space:]]*secrets\.' | grep -qE '>|(^|[[:space:]])tee([[:space:]]|$)' \
   && ! printf '%s\n' "$body" | grep -E '\$\{\{[[:space:]]*secrets\.' | grep -q 'GITHUB_'; then
  reasons+=("a secret is written to a file on disk")
fi
# Broad path / hidden files on an upload.
if [ "$uploads" -eq 1 ]; then
  if printf '%s\n' "$body" | grep -qE 'path:[[:space:]]*["'\'']?(\.|\*\*?)[[:space:]"'\'']*$'; then
    reasons+=("the artifact upload path captures the whole tree")
  fi
  if printf '%s\n' "$body" | grep -qE 'include-hidden-files:[[:space:]]*true'; then
    reasons+=("include-hidden-files: true pulls dotfiles into the artifact")
  fi
fi

if [ "${#reasons[@]}" -gt 0 ]; then
  echo -e "${RED}LEAKY:${NC} a credential can leave this pipeline inside an artifact."
  for r in "${reasons[@]}"; do echo "  - $r"; done
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} no persisted token, no secret on disk, and uploads are scoped to build output."
exit 0
