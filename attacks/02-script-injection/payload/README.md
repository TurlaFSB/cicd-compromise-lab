# Payload — scenario 02 evidence collection

## Approach

The attack payload is delivered entirely through the issue title — no files, no PR, no fork required. When GitHub Actions expands `${{ github.event.issue.title }}` into the `run:` step, embedded shell metacharacters execute as code on the runner.

## Evidence collection strategy

The payload performs two actions to prove the attack path:

1. **Secret access proof** — reads `DUMMY_CLOUD_KEY1` from the environment, computes its SHA-256 hash, and records `secret_present=true` with the hash value. This proves the attacker could read the secret without exposing its raw value.

2. **Evidence persistence** — uses the `gh` CLI (pre-installed on GitHub-hosted runners) to create a new issue in the same repository containing the evidence. The `GITHUB_TOKEN` in scope has `issues: write` permission, so this succeeds. The new issue serves as a durable, timestamped evidence artifact.

## Expected evidence

After a successful attack against the vulnerable workflow:

- A new issue titled `scenario-02-evidence-<run_id>` appears in the target repo
- The issue body contains `secret_present=true` and the SHA-256 hash of `DUMMY_CLOUD_KEY1`
- The workflow run log shows the injected commands executing

## Why this approach

- **Non-destructive** — the payload creates evidence without modifying existing repo content
- **Self-documenting** — the evidence issue proves both code execution and secret access
- **Auditable** — all actions are visible in the repo's issue list and Actions run logs
- **Dummy secrets only** — `DUMMY_CLOUD_KEY1` is a placeholder; no real credentials are at risk
