# Verification — scenario 03 (secret exfiltration)

## Overview

The verification suite proves the hardened workflow eliminates all secret exfiltration vectors through 14 structural checks. It runs offline against the workflow YAML files with no live repository required.

## What is verified

### Detection cross-check (2 checks)

| Check | Assertion |
|---|---|
| 1 | Detection scanner reports **no findings** on the hardened workflow |
| 2 | Detection scanner **correctly flags** the vulnerable workflow |

### Structural invariants (12 checks)

| Check | Invariant | Why it matters |
|---|---|---|
| 3a | Build job does not reference any secrets | Compromised build steps cannot exfiltrate credentials |
| 3b | Build job has `contents: read` permission | Build cannot modify repo content |
| 3c | Build job has no write permissions | Least-privilege enforcement |
| 3d | Deploy job uses `environment:` protection | Required reviewer gate before secret access |
| 3e | No secrets echoed or printed in `run:` steps | Prevents plaintext secret leakage in logs |
| 3f | No secret transformation (base64/hex) | Prevents masking bypass |
| 3g | Permissions are per-job, not workflow-level | Each job gets only what it needs |
| 3h | No secrets in workflow-level `env:` | Secrets not leaked to all jobs |
| 3i | Deploy secrets are step-scoped, not job-scoped | Only the deploy step can access credentials |
| 3j | Actions pinned by commit SHA | Prevents mutable-tag hijack |
| 3k | No mutable tag references | No `@v4` style references that can be silently replaced |
| 3l | Deploy job does not have `contents: write` | Deploy cannot modify repo content |

## How to run

```bash
# Offline structural verification (default)
./verify.sh static

# Full live verification (requires repo setup)
./verify.sh live owner/repo /path/to/target-clone
```

### Static mode

Runs all 14 checks against the hardened workflow file. No network access, no GitHub API, no live repository needed. This is the default mode.

### Live mode

Guides through manual verification steps:

1. Deploy the hardened workflow to the target repository
2. Configure the `production` environment with required reviewers
3. Push a commit and verify the deploy job requires approval
4. Confirm no secrets appear in any log output

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed — hardened workflow blocks exfiltration |
| 1 | One or more checks FAILED |
| 2 | Usage error or missing dependency |

## Results

```
=== Results: 14 passed, 0 failed ===
VERIFICATION PASSED — hardened workflow eliminates secret exfiltration vectors.
```
