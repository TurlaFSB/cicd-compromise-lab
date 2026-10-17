# Verification — Scenario 06: Artifact tampering

## What is verified

10 checks prove the hardened workflow binds build output to what is published:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened workflow | Zero findings on the hardened workflow |
| 2 | Scanner vs. vulnerable workflow | Scanner flags the vulnerable workflow |
| 3a | Simulation vs. vulnerable | Reports TAMPERABLE (no integrity binding) |
| 3b | Simulation vs. hardened | Reports SAFE (attested and verified) |
| 4a | Build attestation | Build job uses `actions/attest-build-provenance` |
| 4b | Verify before publish | `gh attestation verify` appears before `npm publish` |
| 4c | Checksum | A SHA-256 manifest is generated at build and re-checked before publish |
| 4d | Attestation permissions | Build job has `id-token: write` and `attestations: write` |
| 4e | Per-job permissions | No workflow-level `permissions:` block |
| 4f | SHA-pinned actions | All actions pinned by commit SHA |

## How to run

```bash
./verify.sh static              # offline structural checks (default)
./verify.sh live <repo> <clone> # manual live-verification guidance
```

`static` is self-contained: it runs the scanner and the simulation against the hardened and vulnerable workflows and checks the structural invariants. No live repo or network access is needed.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Usage error or missing dependency |
