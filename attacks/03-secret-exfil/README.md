# Attack — scenario 03 (secret exfiltration)

## Overview

This scenario demonstrates **secret exfiltration** from GitHub Actions workflows through multiple credential hygiene failures. The target workflow (`turla-lab-targets/secret-exfil-target`) builds and deploys a project, but violates several credential-handling best practices that enable secret leakage.

Unlike scenarios 01 and 02, which require attacker-supplied input (a malicious PR or issue title), secret exfiltration can occur through passive exposure: misconfigured workflows may leak secrets to anyone who can read build logs, and compromised dependencies can silently exfiltrate credentials without any visible change to the workflow.

## Attack surface

### Vulnerability 1: secrets printed in logs

The deploy step echoes the secret value directly:

```yaml
run: |
  echo "Deploying with key: $DEPLOY_KEY"
```

GitHub Actions masks registered secret values in logs by replacing them with `***`. However, this masking is a best-effort convenience, not a security boundary. It fails when:

- The secret is transformed before output (base64, hex, substring)
- The secret is split across multiple lines
- A non-standard logging method is used (writing to a file, then `cat`)
- `ACTIONS_STEP_DEBUG` is enabled

### Vulnerability 2: masking bypass via transformation

The workflow also base64-encodes the secret before printing:

```yaml
run: |
  echo "Key (b64): $(echo "$DEPLOY_KEY" | base64)"
```

GitHub's log masking matches only the **exact registered value**. The base64-encoded form is a different string, so it passes through the mask unaltered. Anyone with log access can decode it. The same bypass works with:

| Transformation | Command | Bypass mechanism |
|---|---|---|
| Base64 | `echo "$SECRET" \| base64` | Different character set |
| Hex | `echo "$SECRET" \| xxd` | Hex representation |
| Reversed | `echo "$SECRET" \| rev` | Reversed character order |
| Substring | `echo "${SECRET:0:10}"` | Partial value, not exact match |
| URL-encoded | `python3 -c "import urllib.parse; ..."` | Percent-encoded characters |

### Vulnerability 3: overly broad secret scoping

`DEPLOY_KEY` is passed to the build job's `env:` block, even though only the deploy job needs it:

```yaml
jobs:
  build:
    env:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
      DUMMY_CLOUD_KEY: ${{ secrets.DUMMY_CLOUD_KEY1 }}
```

Every step in the build job — including test execution, linting, and dependency installation — can read these secrets. A compromised `npm` package, a malicious test fixture, or a poisoned build plugin can silently exfiltrate the credentials through DNS, HTTP, or embedded in build artifacts.

### Vulnerability 4: debug logging exposure

If `ACTIONS_STEP_DEBUG` is enabled (via repository settings or by re-running a workflow with "Enable debug logging"), the runner prints all environment variables at the start of every step, including secrets. This bypasses log masking entirely because the runner's debug output is not subject to the same redaction rules.

### Vulnerability 5: static long-lived credential

`DEPLOY_KEY` is a static secret that does not expire. If exfiltrated through any of the vectors above, it remains valid indefinitely — until a human notices and manually rotates it. In practice, credential rotation after a CI/CD leak often takes days to weeks, during which the attacker has persistent access.

### Vulnerability 6: overly broad permissions

The workflow declares `contents: write` and `packages: write` at the workflow level:

```yaml
permissions:
  contents: write
  packages: write
```

This gives every job — including the build job, which needs only read access — full write permissions. A compromised build step could push code to the repository or publish malicious packages.

## Evidence

A successful exploitation produces observable evidence:

1. **Workflow run logs** show the secret value in plaintext (or base64-encoded).
2. **Environment variable dumps** in debug-enabled re-runs expose secrets.
3. **Build artifacts** could contain exfiltrated secrets if a dependency smuggles them into the output.
4. **Network logs** (if available) may show outbound connections from compromised steps sending secrets to attacker-controlled endpoints.

The `payload/` directory documents the evidence-collection approach for controlled lab demonstrations.

## MITRE ATT&CK mapping

| Technique | Application |
|---|---|
| T1552 — Unsecured Credentials | Secrets exposed in logs, environment variables, and debug output |
| T1552.001 — Credentials in Files | Secrets available as env vars to all steps in the build job |
| T1020 — Automated Exfiltration | Compromised dependencies can silently exfiltrate secrets |
| T1070.003 — Clear Command History | Base64 transformation of secrets bypasses log masking |

## OWASP CI/CD mapping

| Risk | Application |
|---|---|
| CICD-SEC-6 — Insufficient Credential Hygiene | Secrets printed in logs, overly broad scoping, no environment gates |
| CICD-SEC-5 — Insufficient PBAC | Write permissions granted to all jobs at workflow level |
| CICD-SEC-3 — Dependency Chain Abuse | Actions pinned by mutable tag, allowing silent code changes |

## Fix

See `hardened/03-secret-exfil/deploy.yml` — the fix eliminates all six vectors:

- Per-job least-privilege permissions (build: read-only, deploy: only what it needs)
- Step-scoped secrets (deploy key available only to the deploy step, not the entire job)
- Environment-gated secrets (production environment with required reviewers)
- No secrets in logs (credential used as opaque token, never printed)
- SHA-pinned actions (no mutable tag references)
- Guidance for replacing static keys with OIDC short-lived credentials

The detection scanner in `detections/03-secret-exfil/` identifies vulnerable workflows.

## References

- [GitHub Docs — Using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)
- [GitHub Docs — Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [OWASP CICD-SEC-6 — Insufficient Credential Hygiene](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene)
- [Unit 42 — GitHub Actions Artifacts Leak Tokens](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/)
- [Palo Alto Networks — Leaked Environment Variables in GitHub Actions](https://www.paloaltonetworks.com/blog/prisma-cloud/secrets-leaking-in-github-actions/)
- [StepSecurity — GitHub Actions Runtime Security](https://www.stepsecurity.io/)
