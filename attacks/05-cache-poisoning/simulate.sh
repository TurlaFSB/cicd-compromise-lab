#!/usr/bin/env bash
# simulate.sh — model GitHub Actions cache scoping to show the poisoning path.
#
# This does not call the GitHub API. It reproduces the one rule that makes
# the attack work: a cache entry written by a run on one ref can be RESTORED
# by a run on a child ref — and every branch is a child of the default
# branch. A fork PR's run therefore writes entries the default-branch release
# build will happily restore, as long as the keys match (exactly, or via a
# restore-keys prefix).
#
# The simulation reads the real workflow files so it stays honest: it extracts
# each workflow's cache key and restore-keys and decides, by GitHub's actual
# matching rules, whether the release build would restore the attacker's entry.
#
# Usage:
#   ./simulate.sh                 # run against the vulnerable workflows (default)
#   ./simulate.sh <writer> <victim>   # supply your own two workflow files
#
# Exit codes:
#   0 — the victim build does NOT restore the attacker's entry (safe)
#   1 — the victim build DOES restore the attacker's entry (poisoned)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRITER="${1:-$SCRIPT_DIR/pr-check.yml}"
VICTIM="${2:-$SCRIPT_DIR/release.yml}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WRITER" ] || { echo "no writer workflow at $WRITER" >&2; exit 2; }
[ -f "$VICTIM" ] || { echo "no victim workflow at $VICTIM" >&2; exit 2; }

# Extract the first `key:` value under a cache step (single-line scalar).
cache_key() {
  awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && /^[[:space:]]*key:[[:space:]]*[^[:space:]]/ {
      sub(/^[[:space:]]*key:[[:space:]]*/, ""); print; exit
    }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0 }
  ' "$1"
}

# Extract restore-keys prefixes (block scalar list) for a cache step.
# Entries live on lines strictly more indented than `restore-keys:`; the
# block ends at the first line indented at or below that column.
restore_keys() {
  awk '
    /uses:[[:space:]]*actions\/cache/ { in_cache = 1; next }
    in_cache && match($0, /^[[:space:]]*restore-keys:/) {
      rk_indent = index($0, "restore-keys") - 1
      in_rk = 1; next
    }
    in_rk {
      if ($0 ~ /^[[:space:]]*$/) next           # blank lines inside the block
      match($0, /^[[:space:]]*/)
      if (RLENGTH <= rk_indent) { in_rk = 0 }    # dedent ends the block
      else { line = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line); print line; next }
    }
    in_cache && /^[[:space:]]*-[[:space:]]*uses:/ { in_cache = 0; in_rk = 0 }
  ' "$1"
}

writer_key="$(cache_key "$WRITER")"
victim_key="$(cache_key "$VICTIM")"
victim_restore="$(restore_keys "$VICTIM")"

echo -e "${BOLD}=== Cache-poisoning simulation ===${NC}"
echo "writer (fork PR):   $(basename "$WRITER")  writes key: ${writer_key:-<none>}"
echo "victim (release):   $(basename "$VICTIM")  restores key: ${victim_key:-<none>}"
echo "victim restore-keys: ${victim_restore:-<none>}"
echo

if [ -z "$writer_key" ]; then
  echo -e "${GREEN}SAFE:${NC} the untrusted workflow saves no cache — nothing to poison."
  exit 0
fi

# Does the victim's cache restore match the attacker's written key?
matched=""
if [ -n "$victim_key" ] && [ "$victim_key" = "$writer_key" ]; then
  matched="exact key match ($victim_key)"
fi
if [ -z "$matched" ] && [ -n "$victim_restore" ]; then
  while IFS= read -r pfx; do
    [ -n "$pfx" ] || continue
    case "$writer_key" in
      "$pfx"*) matched="restore-keys prefix '$pfx' matches writer key '$writer_key'"; break ;;
    esac
  done <<< "$victim_restore"
fi

# A key containing hashFiles() is pinned to repository content the attacker
# cannot alter without changing the lockfile, which changes the key. Treat an
# exact match on such a key as non-exploitable via fork PRs.
if [ -n "$matched" ] && printf '%s' "$victim_key" | grep -q 'hashFiles('; then
  echo -e "${GREEN}SAFE:${NC} victim key is bound to hashFiles() — a fork PR cannot forge a"
  echo "       matching entry without altering the lockfile (which changes the key)."
  echo "       $matched, but the hash component defeats it."
  exit 0
fi

if [ -n "$matched" ]; then
  echo -e "${RED}POISONED:${NC} the release build would restore the attacker's cache entry."
  echo "  reason: $matched"
  echo
  echo "  Attack path:"
  echo "   1. Attacker opens a PR from a fork; $(basename "$WRITER") runs their code."
  echo "   2. Their build writes tampered files into a cached path and the entry"
  echo "      is saved under '$writer_key'."
  echo "   3. On the next push to main, $(basename "$VICTIM") restores that entry and"
  echo "      publishes an artifact built from poisoned content."
  exit 1
fi

echo -e "${GREEN}SAFE:${NC} the victim build does not restore any key the untrusted"
echo "       workflow can write. No shared, forgeable cache entry."
exit 0
