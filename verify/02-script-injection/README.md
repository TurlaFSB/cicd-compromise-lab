# Verification — scenario 02 (script injection)

## What it proves

The hardened workflow (`hardened/02-script-injection/triage.yml`) structurally prevents the script injection attack against `turla-lab-targets/script-injection-target`.

## Verification modes

### Static verification (default)

```bash
./verify.sh static
# or simply:
./verify.sh
```

Runs entirely offline. Checks:

1. **Detection cross-check** — the detection scanner (`detections/02-script-injection/detect.sh`) fires on the vulnerable workflow and stays silent on the hardened one.
2. **Structural invariants** of the hardened workflow:
   - No `${{ github.event.* }}` expressions appear in any `run:` block
   - The issue title is passed through an `env:` variable (safe indirection)
   - Shell variable references use double quotes (prevents word splitting)
   - No secrets are referenced in any step
   - `GITHUB_TOKEN` is not explicitly passed (least privilege)
   - Permissions follow least privilege (`contents: read`, `issues: write`, no `contents: write`)
   - Actions are pinned by commit SHA (if any are used)

### Live verification

```bash
./verify.sh live turla-lab-targets/script-injection-target
```

Prints manual steps to deploy the hardened workflow and open a test issue with shell metacharacters in the title. Expected outcome: the title is printed literally in the Actions log — metacharacters are not executed as shell commands.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed — hardened workflow blocks the attack |
| 1 | At least one check failed — the workflow may still be vulnerable |
| 2 | Usage error or missing dependency |
