# Evidence collection — scenario 03 (secret exfiltration)

## Approach

This scenario's attack is **passive exposure** rather than active exploitation. The vulnerable workflow leaks secrets through its own misconfiguration — no attacker-crafted payload is needed to trigger the leak.

### Evidence vectors

1. **Log inspection**: examine workflow run logs for the deploy step. The secret value appears in plaintext in the `echo` output, and the base64-encoded form appears unmasked.

2. **Debug re-run**: re-run the workflow with "Enable debug logging" enabled. The runner dumps all environment variables, including `DEPLOY_KEY`, in the step preamble.

3. **Build job scope**: inspect the build job's step output. While the secret isn't printed intentionally, it is available in the environment — a malicious dependency could read `process.env.DEPLOY_KEY` and exfiltrate it silently.

### Controlled demonstration

For a controlled lab demonstration:

```bash
# 1. Trigger the vulnerable workflow
git commit --allow-empty -m "trigger deploy"
git push origin main

# 2. Check the deploy step's log output
gh run list --repo turla-lab-targets/secret-exfil-target --limit 1
gh run view <run-id> --log --repo turla-lab-targets/secret-exfil-target

# 3. Look for the secret in the output
# Expected: "Deploying with key: <value>"
# Expected: "Key (b64): <base64-encoded-value>"
```

### What the evidence proves

- The secret is readable in plaintext from workflow logs
- The base64-encoded form bypasses GitHub's log masking
- The secret is available to the build job even though only deploy needs it
- No environment gate prevents automated access to the secret

### Safety note

All secrets in the lab are **dummy values**. The `DEPLOY_KEY` and `DUMMY_CLOUD_KEY1` secrets contain placeholder strings with no access to any real system.
