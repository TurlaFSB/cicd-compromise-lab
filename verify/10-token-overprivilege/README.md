# Verification — Scenario 10: GITHUB_TOKEN over-privilege

## What is verified

15 checks prove the hardened workflows scope the token:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened | Zero findings on the hardened set |
| 2 | Scanner vs. vulnerable | Scanner flags the vulnerable set |
| 3a–3d | Vector coverage | WRITE-ALL, NO PERMISSIONS BLOCK, WRITE ON UNTRUSTED TRIGGER and WORKFLOW-LEVEL WRITE each fire |
| 4 | Low-risk grant | `pull-requests: write` on an untrusted trigger is not over-flagged |
| 5a | Simulation vs. vulnerable | Reports OVER-PRIVILEGED |
| 5b | Simulation vs. hardened | Reports scoped |
| 6a | Permissions floor | Every hardened workflow declares a workflow-level block |
| 6b | No write-all | `write-all` absent from the hardened set |
| 6c | No pull_request_target CI | Hardened CI runs on `pull_request` |
| 6d | SHA-pinned actions | All third-party actions pinned by full commit SHA |
| 6e | Read-only CI floor | Hardened CI sets `contents: read` |
| 6f | Job-level release write | `release.yml` keeps write at job level, not workflow level |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
