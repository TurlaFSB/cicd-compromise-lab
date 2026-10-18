# Verification — Scenario 11: workflow_run artifact poisoning

## What is verified

11 checks prove the hardened `workflow_run` handler treats fork output as untrusted data:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened | Zero findings on the hardened consumer |
| 2 | Scanner vs. vulnerable | Scanner flags the vulnerable consumer |
| 3a | Simulation vs. vulnerable | Reports POISONABLE |
| 3b | Simulation vs. hardened | Reports SAFE |
| 4a | Still a `workflow_run` handler | The hardening is meaningful, not a trigger change |
| 4b | No head checkout | The triggering head is never checked out |
| 4c | No artifact execution | Nothing from the artifact/tree is executed |
| 4d | No untrusted context in a shell | No `workflow_run` field is spliced into a command |
| 4e | PR number validated | The value read from the artifact is constrained to digits |
| 4f | Read-only floor | Workflow-level permissions are `contents: read` |
| 4g | SHA-pinned actions | All actions pinned by full commit SHA |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance (two repos, one fork)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
