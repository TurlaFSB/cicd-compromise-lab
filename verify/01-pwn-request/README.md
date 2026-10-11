# Verification — scenario 01 (pwn request)

## What it proves

The hardened workflow (`hardened/01-pwn-request/ci.yml`) structurally prevents the pwn request attack demonstrated in `attacks/01-pwn-request/`.

## Verification modes

### Static verification (default)

```bash
./verify.sh static
# or simply:
./verify.sh
```

Runs entirely offline. Checks:

1. **Detection cross-check** — the detection scanner (`detections/01-pwn-request/detect.sh`) fires on the vulnerable workflow and stays silent on the hardened one.
2. **Structural invariants** of the hardened workflow:
   - The `test` job runs only on `pull_request` (not `pull_request_target`)
   - The `test` job references no secrets
   - The `test` job has read-only permissions
   - The `label` job (which uses `pull_request_target`) has no `actions/checkout` step
   - The `label` job has only `pull-requests: write` permission
   - All actions are pinned by commit SHA (no mutable tags)

### Live verification

```bash
./verify.sh live turla-lab-targets/pwn-request-target /home/claude/pwn-request-target
```

Prints manual steps to deploy the hardened workflow and re-run the attack. Expected outcome: the malicious payload runs in the `test` job but both of its assertions fail (no write token, no secret access), and the `label` job never touches PR code at all.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed — hardened workflow blocks the attack |
| 1 | At least one check failed — the workflow may still be vulnerable |
| 2 | Usage error or missing dependency |
