# Verification — Scenario 05: Cache poisoning

## What is verified

12 checks prove the hardened workflows close the poisoning path:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened pair | Zero findings on the hardened workflows |
| 2 | Scanner vs. vulnerable pair | Scanner flags the vulnerable workflows |
| 3a | Simulation vs. vulnerable pair | Reports POISONED (release restores a fork-writable key) |
| 3b | Simulation vs. hardened pair | Reports SAFE (key is content-bound, writer is read-only) |
| 4a | Read-only writer | PR workflow uses `actions/cache/restore`, not read-write `actions/cache` |
| 4b | Content-bound keys | Every cache key includes `hashFiles()` |
| 4c | No restore-keys | No fuzzy prefix matching in either hardened file |
| 4d | Download-only paths | No `node_modules/`, `dist/`, or other executable dirs cached |
| 4e | Always rebuild | Release runs `npm ci` + `npm run build` unconditionally |
| 4f | Least privilege + gate | Release has per-job permissions and an `environment:` gate |
| 4g | SHA-pinned actions | All actions pinned by commit SHA in both files |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance
```

The `static` mode is self-contained: it copies the workflows into temporary directories, runs the scanner and the simulation, and checks the structural invariants. No live repo or network access is needed.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
