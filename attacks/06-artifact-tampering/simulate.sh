#!/usr/bin/env bash
# simulate.sh — demonstrate artifact tampering and how an integrity binding
# between build and publish defeats it, then judge a workflow for that binding.
#
# Two parts:
#   1. MECHANISM (always runs): build a fake artifact, have the "producer"
#      record its SHA-256 (a stand-in for a SLSA provenance attestation),
#      tamper the bytes with payload/tamper.sh, then show that a consumer
#      which verifies the digest REJECTS the tampered artifact while a
#      consumer which does not verify SHIPS it. This proves the mechanism
#      independently of any specific workflow.
#   2. VERDICT: inspect a workflow file for an integrity binding — a producer
#      that attests/signs/checksums the artifact AND a consumer that verifies
#      before publishing. Reports SAFE or TAMPERABLE and sets the exit code.
#
# Usage:
#   ./simulate.sh                 # judge the vulnerable release.yml (default)
#   ./simulate.sh <workflow.yml>  # judge a specific workflow
#
# Exit codes:
#   0 — the workflow binds build output to publish (tampering is caught)
#   1 — no integrity binding (a tampered artifact would be published)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WF="${1:-$SCRIPT_DIR/release.yml}"
TAMPER="$SCRIPT_DIR/payload/tamper.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$WF" ] || { echo "no workflow at $WF" >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo "need sha256sum" >&2; exit 2; }

echo -e "${BOLD}=== Part 1: tamper mechanism (concrete) ===${NC}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Producer: build an artifact and record its digest (stands in for an
# attestation signed by the build job's OIDC identity).
printf 'export const greet = () => "hello from the real build";\n' > "$work/bundle.js"
attested_digest=$(sha256sum "$work/bundle.js" | awk '{print $1}')
echo "producer built bundle.js and attested digest ${attested_digest:0:16}…"

# Attacker tampers the artifact between upload and download.
bash "$TAMPER" "$work/bundle.js" >/dev/null
actual_digest=$(sha256sum "$work/bundle.js" | awk '{print $1}')
echo "attacker tampered the artifact;    actual digest ${actual_digest:0:16}…"
echo ""

# Consumer WITH verification (hardened behaviour).
if [ "$attested_digest" = "$actual_digest" ]; then
  echo -e "  verifying consumer: digests match — would publish"
else
  echo -e "  verifying consumer: ${GREEN}digest MISMATCH → publish ABORTED${NC} (tamper caught)"
fi
# Consumer WITHOUT verification (vulnerable behaviour).
echo -e "  blind consumer:     ${RED}no check → ships the tampered bytes${NC}"
echo ""

echo -e "${BOLD}=== Part 2: verdict for $(basename "$WF") ===${NC}"

# Producer-side integrity: attestation, signature, or a generated checksum.
producer=0
if grep -qE 'uses:[[:space:]]*actions/attest-build-provenance@' "$WF" \
   || grep -qE 'cosign[[:space:]]+sign' "$WF" \
   || grep -qE 'sha256sum[^|]*>[[:space:]]*\S+' "$WF"; then
  producer=1
fi

# Consumer-side verification before publish.
consumer=0
if grep -qE 'gh[[:space:]]+attestation[[:space:]]+verify' "$WF" \
   || grep -qE 'cosign[[:space:]]+verify' "$WF" \
   || grep -qE 'sha256sum[[:space:]]+(-c|--check)' "$WF"; then
  consumer=1
fi

echo "producer creates an integrity record (attest/sign/checksum): $([ $producer -eq 1 ] && echo yes || echo no)"
echo "consumer verifies it before publishing:                      $([ $consumer -eq 1 ] && echo yes || echo no)"
echo ""

if [ "$producer" -eq 1 ] && [ "$consumer" -eq 1 ]; then
  echo -e "${GREEN}SAFE:${NC} build output is cryptographically bound to what is published;"
  echo "       a tampered artifact fails verification and is never shipped."
  exit 0
fi

echo -e "${RED}TAMPERABLE:${NC} nothing binds the build output to the published artifact."
echo "  Any actor able to write the artifact between build and publish can swap"
echo "  the bytes, and the publish step will ship them unverified."
exit 1
