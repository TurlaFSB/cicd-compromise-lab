#!/usr/bin/env bash
# simulate.sh — show what a trust policy will and will not admit, offline.
#
# A live demo needs a real AWS account and an OIDC provider. This models the
# decision AWS STS makes: it takes the policy's conditions on
# token.actions.githubusercontent.com:sub / :aud and tests a set of example
# OIDC token subjects against them, the way StringEquals / StringLike match.
#
#   Part 1 (MATCHING, always runs): evaluate four example subjects —
#     the intended repo+ref, a different branch of the same repo, a different
#     repo in the same org, and an unrelated attacker repo — and print which
#     the policy would ADMIT.
#   Part 2 (VERDICT): a policy is EXPLOITABLE if it admits anything beyond the
#     single intended subject, or if it fails to constrain the audience.
#
# Usage:
#   ./simulate.sh                        # judge the vulnerable trust-policy.json
#   ./simulate.sh <trust-policy.json>    # judge a specific policy
#
# Exit codes: 0 safe (only the intended subject, audience pinned), 1 exploitable,
#             2 usage/dependency error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POL="${1:-$SCRIPT_DIR/trust-policy.json}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

[ -f "$POL" ] || { echo "no trust policy at $POL" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 2; }

# The intended identity this role is meant for.
INTENDED="repo:turla-lab-targets/oidc-trust-target:ref:refs/heads/main"

echo -e "${BOLD}=== Part 1: which OIDC subjects does $(basename "$POL") admit? ===${NC}"

out=$(python3 -I - "$POL" "$INTENDED" <<'PY'
import json, sys, fnmatch

PROVIDER = "token.actions.githubusercontent.com"
path, intended = sys.argv[1], sys.argv[2]
doc = json.load(open(path, encoding="utf-8"))

def as_list(x):
    return [] if x is None else (x if isinstance(x, list) else [x])

sub_eq, sub_like, aud_present = [], [], False
for st in as_list(doc.get("Statement")):
    if not isinstance(st, dict):
        continue
    cond = st.get("Condition", {})
    for op, mapping in (cond.items() if isinstance(cond, dict) else []):
        if not isinstance(mapping, dict):
            continue
        for k, v in mapping.items():
            kl = k.lower()
            if kl == f"{PROVIDER}:sub":
                (sub_eq if op.startswith("StringEquals") else sub_like).extend(as_list(v))
            if kl == f"{PROVIDER}:aud":
                aud_present = True

def admits(subject):
    if sub_eq and subject in sub_eq:
        return True
    for pat in sub_like:
        if fnmatch.fnmatch(subject, pat):
            return True
    # No sub condition at all → any subject is admitted.
    return not sub_eq and not sub_like

samples = [
    ("intended repo + ref",        intended),
    ("same repo, other branch",    "repo:turla-lab-targets/oidc-trust-target:ref:refs/heads/attacker"),
    ("other repo in the org",      "repo:turla-lab-targets/some-other-repo:ref:refs/heads/main"),
    ("unrelated attacker repo",    "repo:attacker-org/evil:ref:refs/heads/main"),
]

admitted = []
for label, subj in samples:
    ok = admits(subj)
    admitted.append((label, subj, ok))
    mark = "ADMIT " if ok else "deny  "
    print(f"  {mark} {label:28} {subj}")

extra = [l for (l, s, ok) in admitted if ok and s != intended]
print(f"AUD_PINNED={'yes' if aud_present else 'no'}")
print("EXTRA=" + ("|".join(extra) if extra else ""))
PY
)

# Show the per-subject matching lines (everything except the marker lines).
printf '%s\n' "$out" | grep -vE '^(AUD_PINNED=|EXTRA=)'

aud_pinned=$(printf '%s\n' "$out" | sed -n 's/^AUD_PINNED=//p')
extra=$(printf '%s\n' "$out" | sed -n 's/^EXTRA=//p')

echo ""
echo -e "${BOLD}=== Part 2: verdict for $(basename "$POL") ===${NC}"
echo "audience constrained (:aud condition present): $aud_pinned"

problems=0
if [ -n "$extra" ]; then
  echo -e "${RED}over-broad subject:${NC} the policy also admits — $(printf '%s' "$extra" | tr '|' ';')"
  problems=1
fi
if [ "$aud_pinned" != "yes" ]; then
  echo -e "${RED}unconstrained audience:${NC} no :aud condition, so a token minted for another audience is accepted"
  problems=1
fi

echo ""
if [ "$problems" -eq 0 ]; then
  echo -e "${GREEN}SAFE:${NC} only the intended repo+ref is admitted and the audience is pinned."
  exit 0
fi
echo -e "${RED}EXPLOITABLE:${NC} the trust policy admits identities beyond the one intended workflow."
echo "  Any GitHub Actions run matching the over-broad condition can assume this role."
exit 1
