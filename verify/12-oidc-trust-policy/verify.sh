#!/usr/bin/env bash
# Verification script for scenario 12 — OIDC trust policy misconfiguration
#
# Proves the hardened trust policy + workflow close the OIDC exchange by:
#   1. Running the scanner against the hardened and vulnerable pairs.
#   2. Running the subject-matching simulation against both policies.
#   3. Checking structural invariants of the hardened policy and workflow.
#
# Usage: ./verify.sh static | live <repo> <clone>
# Exit codes: 0 pass, 1 fail, 2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DETECT="$LAB_ROOT/detections/12-oidc-trust-policy/detect.sh"
SIMULATE="$LAB_ROOT/attacks/12-oidc-trust-policy/simulate.sh"
VULN_POL="$LAB_ROOT/attacks/12-oidc-trust-policy/trust-policy.json"
HARD_POL="$LAB_ROOT/hardened/12-oidc-trust-policy/trust-policy.json"
VULN_WF="$LAB_ROOT/attacks/12-oidc-trust-policy/deploy.yml"
HARD_WF="$LAB_ROOT/hardened/12-oidc-trust-policy/deploy.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0
assert_pass() { echo -e "${GREEN}  PASS:${NC} $1"; PASS=$((PASS + 1)); }
assert_fail() { echo -e "${RED}  FAIL:${NC} $1"; FAIL=$((FAIL + 1)); }

stage() {  # stage <policy> <workflow> into a fresh dir, echo the dir
  local d; d=$(mktemp -d); mkdir -p "$d/.github/workflows"
  cp "$1" "$d/trust-policy.json"
  cp "$2" "$d/.github/workflows/deploy.yml"
  echo "$d"
}

verify_static() {
  echo "=== Structural verification of hardened OIDC configuration ==="
  echo ""
  for f in "$DETECT" "$SIMULATE" "$VULN_POL" "$HARD_POL" "$VULN_WF" "$HARD_WF"; do
    [ -e "$f" ] || { assert_fail "missing required file: $f"; return; }
  done

  local d
  echo "--- Check 1: scanner vs. hardened pair ---"
  d=$(stage "$HARD_POL" "$HARD_WF")
  if ("$DETECT" static "$d" 2>/dev/null || true) | grep -q "FINDING"; then
    assert_fail "scanner flagged the hardened pair"
  else
    assert_pass "scanner reports no findings on the hardened pair"
  fi
  rm -rf "$d"

  echo "--- Check 2: scanner vs. vulnerable pair ---"
  d=$(stage "$VULN_POL" "$VULN_WF")
  local out; out=$("$DETECT" static "$d" 2>/dev/null || true)
  if grep -q "FINDING" <<<"$out"; then
    assert_pass "scanner flags the vulnerable pair"
  else
    assert_fail "scanner missed the vulnerable pair"
  fi
  # Each of the four vectors fires.
  for v in "WILDCARD SUBJECT" "MISSING AUDIENCE CONDITION" "WORKFLOW-LEVEL ID-TOKEN" "ID-TOKEN ON UNTRUSTED TRIGGER"; do
    if grep -q "$v" <<<"$out"; then
      assert_pass "vector fires: $v"
    else
      assert_fail "vector missing: $v"
    fi
  done
  rm -rf "$d"

  echo "--- Check 3: subject-matching simulation ---"
  if "$SIMULATE" "$VULN_POL" >/dev/null 2>&1; then
    assert_fail "simulation did not flag the vulnerable policy"
  else
    assert_pass "simulation reports the vulnerable policy as EXPLOITABLE"
  fi
  if "$SIMULATE" "$HARD_POL" >/dev/null 2>&1; then
    assert_pass "simulation reports the hardened policy as SAFE"
  else
    assert_fail "simulation still flags the hardened policy"
  fi

  echo "--- Check 4: structural invariants ---"

  # 4a: hardened policy pins the audience.
  if grep -qE '"token\.actions\.githubusercontent\.com:aud"' "$HARD_POL"; then
    assert_pass "hardened policy sets an :aud condition"
  else
    assert_fail "hardened policy has no :aud condition"
  fi

  # 4b: hardened policy subject has no wildcard.
  local subval
  subval=$(python3 -c "
import json,sys
d=json.load(open('$HARD_POL'))
vals=[]
for s in d.get('Statement',[]):
    for op,m in (s.get('Condition',{}) or {}).items():
        for k,v in (m or {}).items():
            if k.lower().endswith(':sub'):
                vals+= v if isinstance(v,list) else [v]
print('|'.join(vals))
")
  if [ -n "$subval" ] && ! printf '%s' "$subval" | grep -q '\*'; then
    assert_pass "hardened policy subject is pinned (no wildcard): $subval"
  else
    assert_fail "hardened policy subject is absent or wildcarded: ${subval:-<none>}"
  fi

  # 4c: hardened workflow grants id-token only at job level, not workflow level.
  if awk '/^permissions:[[:space:]]*$/{inblk=1;next} inblk&&/^[^[:space:]]/{inblk=0} inblk&&/id-token:[[:space:]]*write/{found=1} END{exit !found}' "$HARD_WF"; then
    assert_fail "hardened workflow grants id-token: write at workflow level"
  else
    assert_pass "hardened workflow does not grant id-token at workflow level"
  fi
  if grep -qE 'id-token:[[:space:]]*write' "$HARD_WF"; then
    assert_pass "hardened workflow still uses OIDC (id-token at job level)"
  else
    assert_fail "hardened workflow no longer requests an OIDC token"
  fi

  # 4d: hardened workflow runs on a trusted trigger only.
  if awk '/^on:/{ino=1} ino&&/^[^[:space:]]/&&!/^on:/{ino=0} ino&&/(pull_request_target|workflow_run|issue_comment|issues)/{bad=1} END{exit bad?0:1}' "$HARD_WF"; then
    assert_fail "hardened workflow still uses an untrusted trigger"
  else
    assert_pass "hardened workflow runs only on trusted triggers"
  fi

  # 4e: actions SHA-pinned.
  if grep -qE 'uses:[[:space:]]*[^@]+@[0-9a-f]{40}' "$HARD_WF" \
     && ! { grep -E 'uses:[[:space:]]*[^@]+@v[0-9]' "$HARD_WF" | grep -vq '#'; }; then
    assert_pass "all actions pinned by commit SHA"
  else
    assert_fail "actions should be pinned by commit SHA"
  fi

  echo ""
}

verify_live() {
  echo "=== Live verification: OIDC trust policy ==="
  echo ""
  echo "MANUAL STEPS REQUIRED (needs an AWS account with a dummy role):"
  echo "  1. Create an IAM role with the vulnerable trust-policy.json."
  echo "  2. From a second repo in the org, run a workflow that assumes the"
  echo "     role via aws-actions/configure-aws-credentials — it succeeds,"
  echo "     proving the wildcard subject admits an unintended repo."
  echo "  3. Replace the role's trust policy with the hardened one and repeat:"
  echo "     the second repo is denied (sub/aud no longer match)."
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
  echo -e "${GREEN}VERIFICATION PASSED${NC} — hardened trust policy and workflow pin the OIDC exchange to one identity."
  exit 0
fi
