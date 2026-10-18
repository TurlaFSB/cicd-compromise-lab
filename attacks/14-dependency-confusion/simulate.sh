#!/usr/bin/env bash
# simulate.sh — demonstrate dependency confusion and install-script abuse
# offline, then judge a scenario directory (ci.yml + .npmrc + package.json).
#
#   Part 1 (MECHANISM, always runs):
#     a) Resolution: the internal registry has @turla-lab/internal-utils@1.2.0;
#        an attacker has published the same name publicly at 9.9.9. With the
#        scope pinned in .npmrc, resolution stays internal (1.2.0); unpinned,
#        npm takes the highest version across registries — the public 9.9.9.
#     b) Install scripts: a dependency ships a postinstall script. `npm install`
#        runs it (attacker code executes); `npm ci --ignore-scripts` does not.
#
#   Part 2 (VERDICT): inspect the directory's ci.yml + .npmrc + package.json
#     for the unsafe patterns and report VULNERABLE (exit 1) or SAFE (exit 0).
#
# Usage:
#   ./simulate.sh            # judge this directory (attacks/14)
#   ./simulate.sh <dir>      # judge a scenario directory
#
# Exit codes: 0 safe, 1 vulnerable, 2 usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-$SCRIPT_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -d "$DIR" ] || { echo "no directory at $DIR" >&2; exit 2; }
NPMRC="$DIR/.npmrc"
CI="$DIR/ci.yml"

# Comment-stripped workflow body, so prose in header comments (which may
# mention "--ignore-scripts", "npm install", etc.) never matches.
ci_body=""
[ -f "$CI" ] && ci_body=$(grep -vE '^[[:space:]]*#' "$CI")

echo -e "${BOLD}=== Part 1: resolution and install-script mechanism ===${NC}"

SCOPE="@turla-lab"
pinned=0
[ -f "$NPMRC" ] && grep -qE "^${SCOPE}:registry=" "$NPMRC" && pinned=1

internal_ver="1.2.0"
public_ver="9.9.9"   # attacker-published, same name, higher version
if [ "$pinned" -eq 1 ]; then
  echo -e "  scope pinned → ${SCOPE}/internal-utils resolves to the internal ${GREEN}${internal_ver}${NC} (public ${public_ver} ignored)"
else
  echo -e "  scope NOT pinned → npm takes the highest version across registries: the ${RED}public ${public_ver}${NC} (attacker) wins over internal ${internal_ver}"
fi

# Install-script demonstration in a sandbox.
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pkg_script="$work/postinstall.sh"
printf '#!/bin/sh\necho pwned > "%s/postinstall.proof"\n' "$work" > "$pkg_script"
chmod +x "$pkg_script"

ignore_scripts=0
printf '%s\n' "$ci_body" | grep -qE -- '--ignore-scripts' && ignore_scripts=1
[ -f "$NPMRC" ] && grep -qE '^ignore-scripts=true' "$NPMRC" && ignore_scripts=1

if [ "$ignore_scripts" -eq 1 ]; then
  echo -e "  install with --ignore-scripts → dependency postinstall ${GREEN}does not run${NC}"
else
  sh "$pkg_script"
  if [ -f "$work/postinstall.proof" ]; then
    echo -e "  install with scripts enabled → dependency postinstall ${RED}executed${NC} (attacker code ran at install time)"
  fi
fi
echo ""

echo -e "${BOLD}=== Part 2: verdict for ${DIR##*/}/ ===${NC}"
reasons=()

if [ -f "$CI" ]; then
  if printf '%s\n' "$ci_body" | grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash)([[:space:]]|$)'; then
    reasons+=("a remote script is piped into a shell")
  fi
  if printf '%s\n' "$ci_body" | grep -qE 'npm[[:space:]]+(install|i)([[:space:]]|$)'; then
    reasons+=("'npm install' resolves versions fresh (use npm ci)")
  fi
  if printf '%s\n' "$ci_body" | grep -qE 'npm[[:space:]]+(install|i|ci)' && [ "$ignore_scripts" -eq 0 ]; then
    reasons+=("install runs lifecycle scripts (no --ignore-scripts)")
  fi
fi
if [ "$pinned" -eq 0 ] && [ -f "$DIR/package.json" ] && grep -qE "\"${SCOPE}/" "$DIR/package.json"; then
  reasons+=("the ${SCOPE} scope is not pinned to a registry (dependency confusion)")
fi

if [ "${#reasons[@]}" -gt 0 ]; then
  echo -e "${RED}VULNERABLE:${NC} the install phase can run attacker code or pull an attacker package."
  for r in "${reasons[@]}"; do echo "  - $r"; done
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} locked install, scripts disabled, scope pinned, nothing piped from the network into a shell."
exit 0
