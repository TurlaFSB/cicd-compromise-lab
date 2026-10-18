# Verification — Scenario 12: OIDC trust policy misconfiguration

## What is verified

14 checks prove the hardened trust policy and workflow pin the OIDC exchange to one identity:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened | Zero findings on the hardened policy + workflow |
| 2 | Scanner vs. vulnerable | Scanner flags the vulnerable pair |
| 2a–2d | Vector coverage | WILDCARD SUBJECT, MISSING AUDIENCE, WORKFLOW-LEVEL ID-TOKEN, ID-TOKEN ON UNTRUSTED TRIGGER each fire |
| 3a | Simulation vs. vulnerable | Reports EXPLOITABLE |
| 3b | Simulation vs. hardened | Reports SAFE |
| 4a | Audience pinned | Hardened policy sets an `:aud` condition |
| 4b | Subject pinned | Hardened policy `sub` has no wildcard |
| 4c | Job-level id-token | Hardened workflow grants `id-token: write` on the job, not workflow-wide |
| 4c' | Still uses OIDC | Hardened workflow keeps `id-token: write` (keyless auth retained) |
| 4d | Trusted trigger | Hardened workflow runs on no untrusted trigger |
| 4e | SHA-pinned actions | All actions pinned by full commit SHA |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance (needs an AWS role)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
