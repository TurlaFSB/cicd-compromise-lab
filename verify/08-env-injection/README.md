# Verification — Scenario 08: GITHUB_ENV / GITHUB_PATH injection

## What is verified

9 checks prove the hardened workflow keeps untrusted data out of the runner environment files:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened workflow | Zero findings on the hardened workflow |
| 2 | Scanner vs. vulnerable workflow | Scanner flags the vulnerable workflow |
| 3a | Simulation vs. vulnerable | Reports INJECTABLE (untrusted reaches env files) |
| 3b | Simulation vs. hardened | Reports SAFE |
| 4a | No untrusted to env files | No `${{ github.event.* }}` written to `$GITHUB_ENV`/`$GITHUB_PATH` |
| 4b | No GITHUB_PATH write | `$GITHUB_PATH` is never written |
| 4c | Title via env: | Untrusted title exposed only through step-scoped `env:` |
| 4d | Heredoc delimiter | Any `$GITHUB_ENV` write uses a heredoc delimiter (fixed name) |
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
