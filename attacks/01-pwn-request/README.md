# Scenario 01 — Pwn request

**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **MITRE ATT&CK:** T1195 (Supply Chain Compromise)

## Target

[`turla-lab-targets/pwn-request-target`](https://github.com/turla-lab-targets/pwn-request-target) — `.github/workflows/ci.yml` there.

## The vulnerability

The target's workflow triggers on `pull_request_target`, which runs with the base repository's `GITHUB_TOKEN` and secrets regardless of who opened the PR or where it came from. It then checks out the PR's own head commit (`github.event.pull_request.head.sha`) and runs `npm ci && npm test` against it.

Since the PR author controls every file in their own PR — including `tests/` — they control what code the workflow executes, with that workflow's token and secret access. No approval, review, or merge is required; the workflow runs the moment the PR is opened.

## Attack

`attack.sh`:
1. Branches off the target's `main`, replaces `tests/evil.test.js` with `payload/evil.test.js`, commits with an innocuous-looking message, and pushes.
2. Opens a PR against the target via the REST API (not `gh pr create`, which needs GraphQL — blocked in this environment).
3. Polls the triggered `pull_request_target` run to completion.
4. Pulls back the run metadata and the PR's comments as evidence.

The payload (`payload/evil.test.js`), running inside the vulnerable workflow, does two things:
1. Uses `GITHUB_TOKEN` from its environment to post a comment on the very PR that triggered it — direct proof of write access granted to PR-controlled code.
2. Checks that `DUMMY_CLOUD_KEY` (a lab secret) is present and non-empty, then hashes it — proof the secret was reachable, without ever printing or storing the raw value.

## Evidence

Run: [turla-lab-targets/pwn-request-target#2 / run 38111846252](https://github.com/turla-lab-targets/pwn-request-target/actions/runs/38111846252) — `completed` / `success`.

- `evidence/run-metadata.json` — the full run object from the Actions API.
- `evidence/pr-comments.json` — the PR comment posted by the payload, timestamped and attributed to `github-actions[bot]`, using the workflow's `GITHUB_TOKEN`:

  > **Scenario 01 evidence — pwn request**
  >
  > This comment was posted by test code that shipped inside this PR, executed by the target repo's `pull_request_target` workflow...
  > It had write access to `GITHUB_TOKEN` purely because the PR was opened — no approval, no review, no merge.

- The "Run tests" job step completed successfully, which only happens if both of the payload's assertions passed: the PR comment posted (HTTP 201) **and** `DUMMY_CLOUD_KEY` was present and non-empty when read from PR-controlled code.

**Note on the artifact:** the payload also writes `evidence.json` and uploads it as a workflow artifact. Downloading that artifact in this environment is blocked (Azure Blob Storage egress is denied by the sandbox's network policy) — this is an environment limitation, not a gap in the attack. The run metadata and PR comment above are sufficient proof on their own; the artifact download works normally from a browser or an unrestricted CI runner.

### A caught mistake, left visible on purpose

The first version of the payload asserted `secretHash.length === 64` as proof the secret was reachable. That's wrong: `sha256("")` is also 64 hex characters, so the assertion would have passed even if the secret were empty or unset. It was caught before this write-up was finalized and fixed to assert truthiness of the raw value *before* hashing it (`payload/evil.test.js`, commit history). The run cited above is from the corrected payload.

## Fix direction

See `hardened/01-pwn-request/`. Summary: never check out and execute a PR's own code under `pull_request_target`. Either split into an unprivileged job (triggered by plain `pull_request`, no secrets, builds/tests the PR's code) and a privileged job (triggered by `pull_request_target`, never checks out PR code, only acts on trusted data), or gate the privileged path behind an environment with required reviewers.
