# Verification — Scenario 14: dependency confusion / install-script abuse

## What is verified

15 checks prove the hardened install phase resists both attacks:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened | Zero findings on the hardened config |
| 2 | Scanner vs. vulnerable | Scanner flags the vulnerable config |
| 2a–2d | Vector coverage | PIPE TO SHELL, NO LOCKFILE INSTALL, INSTALL SCRIPTS ENABLED, UNPINNED SCOPE each fire |
| 3a | Simulation vs. vulnerable | Reports VULNERABLE (public package wins; postinstall runs) |
| 3b | Simulation vs. hardened | Reports SAFE |
| 4a | Locked install | Hardened workflow uses `npm ci`, not `npm install` |
| 4b | Scripts disabled | Install uses `--ignore-scripts` |
| 4c | No pipe-to-shell | No remote script piped into a shell |
| 4d | Verified fetch | The fetched bootstrap is checksum-verified |
| 4e | Scope pinned | `.npmrc` pins `@turla-lab` and sets `ignore-scripts=true` |
| 4f | SHA-pinned actions | All actions pinned by full commit SHA |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance (needs a registry)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
