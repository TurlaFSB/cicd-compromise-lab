#!/usr/bin/env bash
# Verification script for scenario 06 — artifact tampering
#
# Proves the hardened workflow binds build output to what is published by:
#   1. Running the detection scanner against the hardened and vulnerable
#      workflows — vulnerable triggers findings, hardened does not.
#   2. Running the tamper simulation against both — it reports TAMPERABLE for
#      the vulnerable workflow and SAFE for the hardened one.
#   3. Checking structural invariants of the hardened workflow.
#
# Usage:
#   ./verify.sh static              # offline structural checks (default)
#   ./verify.sh live <repo> <clone> # manual live-verification guidance
#
# Exit codes:
#   0 — verification passed
#   1 — verification FAILED
#   2 — usage error or missing dependency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/06-artifact-tampering/detect.sh"
SIMULATE="$LAB_ROOT/attacks/06-artifact-tampering/simulate.sh"
VULN_WF="$LAB_ROOT/attacks/06-artifact-tampering/release.yml"
HARD_WF="$LAB_ROOT/hardened/06-artifact-tampering/release.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

verify_static() {
  echo "=== Structural verification of hardened workflow ==="
  echo ""

  for f in "$DETECT" "$SIMULATE" "$HARD_WF" "$VULN_WF"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  # --- Check 1: scanner clears the hardened workflow ---
  echo "--- Check 1: detection scanner vs. hardened workflow ---"
  local tmp
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$HARD_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened workflow"
  else
    assert_pass "scanner reports no findings on the hardened workflow"
  fi
  rm -rf "$tmp"

  # --- Check 2: scanner flags the vulnerable workflow ---
  echo "--- Check 2: detection scanner vs. vulnerable workflow ---"
  tmp=$(mktemp -d); mkdir -p "$tmp/.github/workflows"
  cp "$VULN_WF" "$tmp/.github/workflows/"
  if ("$DETECT" static "$tmp" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_pass "scanner correctly flags the vulnerable workflow"
  else
    assert_fail "scanner missed the vulnerable workflow"
  fi
  rm -rf "$tmp"

  # --- Check 3: simulation TAMPERABLE on vulnerable, SAFE on hardened ---
  echo "--- Check 3: tamper simulation ---"
  if "$SIMULATE" "$VULN_WF" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable workflow as tamperable"
  else
    assert_pass "simulation reports the vulnerable workflow as TAMPERABLE"
  fi
  if "$SIMULATE" "$HARD_WF" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened workflow as SAFE"
  else
    assert_fail "simulation still reports the hardened workflow as tamperable"
  fi

  # --- Check 4: structural invariants ---
  echo "--- Check 4: structural invariants ---"

  # 4a: build job attests build provenance
  if grep -qE 'uses:[[:space:]]*actions/attest-build-provenance@' "$HARD_WF"; then
    assert_pass "build job generates a signed build-provenance attestation"
  else
    assert_fail "build job should use actions/attest-build-provenance"
  fi

  # 4b: publish job verifies the attestation before publishing
  local before_publish
  before_publish=$(awk '
    /gh[[:space:]]+attestation[[:space:]]+verify/ { seen_verify = 1 }
    /npm[[:space:]]+publish/ { if (seen_verify) print "ok"; else print "bad"; exit }
  ' "$HARD_WF")
  if [ "$before_publish" = "ok" ]; then
    assert_pass "attestation is verified before publish (verify precedes npm publish)"
  else
    assert_fail "publish must be gated by gh attestation verify appearing before it"
  fi

  # 4c: a checksum is generated and checked
  if grep -qE 'sha256sum[^|]*>' "$HARD_WF" && grep -qE 'sha256sum[[:space:]]+(-c|--check)' "$HARD_WF"; then
    assert_pass "checksum generated at build and re-checked before publish"
  else
    assert_fail "expected a sha256 checksum generated and re-checked"
  fi

  # 4d: build job has id-token + attestations write permissions
  local build_section
  build_section=$(awk '
    /^[[:space:]]+build:/ { in_build = 1 }
    in_build && /^[[:space:]]{2}[a-zA-Z]/ && !/^[[:space:]]+build:/ { in_build = 0 }
    in_build { print }
  ' "$HARD_WF")
  if echo "$build_section" | grep -qE 'id-token:[[:space:]]*write' \
     && echo "$build_section" | grep -qE 'attestations:[[:space:]]*write'; then
    assert_pass "build job has id-token: write and attestations: write"
  else
    assert_fail "build job needs id-token: write and attestations: write for attestation"
  fi

  # 4e: no workflow-level permissions (per-job only)
  if awk '/^permissions:/{print; exit}' "$HARD_WF" | grep -q .; then
    assert_fail "permissions declared at workflow level — should be per-job"
  else
    assert_pass "permissions are per-job, not workflow-level"
  fi

  # 4f: actions SHA-pinned, no mutable tags
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA, not mutable tags"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: artifact tampering ==="
  echo ""
  echo "MANUAL STEPS REQUIRED:"
  echo "  1. Deploy the vulnerable release.yml to a target repo and push a v* tag."
  echo "  2. Between build and publish, tamper the artifact (payload/tamper.sh)"
  echo "     via a malicious step or a second workflow — the publish ships it."
  echo "  3. Replace with hardened/06-artifact-tampering/release.yml and repeat:"
  echo "     gh attestation verify fails on the tampered bytes and publish aborts."
  echo ""
}

case "${1:-}" in
  static) verify_static ;;
  live)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      echo "usage: $0 live <owner/repo> <target-clone-path>" >&2
      exit 2
    fi
    verify_live "$2" "$3"
    ;;
  *) verify_static ;;
esac

echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}VERIFICATION FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened workflow binds build output to what is published."
  exit 0
fi
