# Verification — Scenario 13: credential leakage via artifacts

## What is verified

14 checks prove the hardened workflow keeps credentials out of uploaded artifacts:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened | Zero findings on the hardened workflow |
| 2 | Scanner vs. vulnerable | Scanner flags the vulnerable workflow |
| 2a–2d | Vector coverage | PERSISTED CHECKOUT CREDENTIAL, SECRET WRITTEN TO FILE, BROAD ARTIFACT PATH, HIDDEN FILES IN ARTIFACT each fire |
| 3a | Simulation vs. vulnerable | Reports LEAKY (secret found in the broad archive) |
| 3b | Simulation vs. hardened | Reports SAFE (narrow archive carries no secret) |
| 4a | Persist disabled | `persist-credentials: false` on checkout |
| 4b | No secret on disk | No `${{ secrets.* }}` redirected to a file |
| 4c | Secret via env | The npm token is exposed through `NODE_AUTH_TOKEN` env |
| 4d | Narrow upload | Upload path is not `.`/`**`, and `include-hidden-files` is not true |
| 4e | SHA-pinned actions | All actions pinned by full commit SHA |

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
