# Verification — Scenario 09: Reusable workflow trust boundary

## What is verified

7 checks prove the hardened caller invokes the reusable workflow safely:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened caller | Zero findings on the hardened caller |
| 2 | Scanner vs. vulnerable caller | Scanner flags the vulnerable caller |
| 3a | SHA pin | Reusable workflow pinned by a full 40-char commit SHA |
| 3b | No mutable ref | No `@main`/`@vN`/`@latest` on the reusable workflow |
| 3c | No inherit | No `secrets: inherit` |
| 3d | Explicit secrets | Any secrets passed are named explicitly |
| 3e | Version comment | The pinned SHA carries a version comment |

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
