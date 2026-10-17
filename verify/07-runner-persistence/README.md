# Verification — Scenario 07: Self-hosted runner persistence

## What is verified

9 checks prove the hardened workflow removes the persistence exposure:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened workflow | Zero findings on the hardened workflow |
| 2 | Scanner vs. vulnerable workflow | Scanner flags the vulnerable workflow |
| 3a | Simulation vs. vulnerable | Reports PERSISTS (untrusted code on self-hosted) |
| 3b | Simulation vs. hardened | Reports SAFE (GitHub-hosted / ephemeral) |
| 4a | Hosted runner | The untrusted-trigger job runs on a GitHub-hosted runner |
| 4b | No self-hosted | No `self-hosted` runner anywhere in the workflow |
| 4c | No persistence step | No crontab/shell-profile/systemd/autostart writes |
| 4d | Least privilege | Read-only permissions declared |
| 4e | SHA-pinned actions | All actions pinned by commit SHA |

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
