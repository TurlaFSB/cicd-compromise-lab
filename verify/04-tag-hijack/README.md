# Verification — Scenario 04: Mutable action tag hijack

## What is verified

The verification script proves that the hardened workflow eliminates the mutable action tag hijack attack surface through 13 structural checks:

| # | Check | What it proves |
|---|---|---|
| 1 | Scanner vs. hardened workflow | Detection scanner reports zero findings |
| 2 | Scanner vs. vulnerable workflow | Detection scanner correctly identifies all 11 mutable tag references |
| 2b | Scanner false-positive regression | `statuses: read` and expression-built local paths are not reported as action refs |
| 3a | SHA pinning completeness | Every `uses:` line contains a full 40-character commit SHA |
| 3b | No version tags | No `@vN` references remain in any `uses:` line |
| 3c | No branch refs | No `@main`, `@master`, or `@develop` references |
| 3d | Version comments | Every SHA-pinned action has a human-readable version in a trailing comment |
| 3e | Per-job permissions | No workflow-level `permissions:` block; each job declares its own |
| 3f | No workflow-level secrets | No `secrets.*` in workflow-level `env:` block |
| 3g | Credential hygiene | All `actions/checkout` steps set `persist-credentials: false` |
| 3h | Job-level permissions | All 4 jobs have their own `permissions:` block |
| 3i | Environment protection | Deploy job uses `environment:` with protection rules |
| 3j | Least-privilege | No job has `contents: write` permission |

## How to run

### Static verification (offline, no live repo needed)

```bash
./verify.sh static
```

This is the default mode and runs all 13 checks against the hardened workflow file and the detection scanner.

### Live verification (requires target repos)

```bash
./verify.sh live <owner/repo> <target-clone-path>
```

Prints manual steps for a full end-to-end tag hijack simulation:
1. Deploy the vulnerable workflow to a target repo
2. Push a commit and observe normal action execution
3. Force-push the `@v1` tag on the helper action to a compromised commit
4. Push another commit and observe the compromised code running
5. Replace with the hardened workflow and repeat — the pinned SHA is unaffected

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed — hardened workflow is secure |
| `1` | One or more checks failed — hardened workflow still vulnerable |
| `2` | Usage error or missing dependency |
