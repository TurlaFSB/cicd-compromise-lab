# Hardening — scenario 03 (secret exfiltration)

## Summary

The hardened workflow eliminates six credential hygiene failures that enabled secret exfiltration from the vulnerable pipeline.

## Before and after

| Vector | Vulnerable | Hardened |
|---|---|---|
| Secret in logs | `echo "Deploying with key: $DEPLOY_KEY"` | Secret used as opaque token, never printed |
| Masking bypass | `echo "$DEPLOY_KEY" \| base64` prints unmasked | No secret transformation in any step |
| Broad secret scope | `DEPLOY_KEY` in build job env | Build job has zero secrets; deploy secret is step-scoped |
| No environment gate | Deploy runs automatically on push | `environment: production` with required reviewers |
| Broad permissions | `contents: write` + `packages: write` at workflow level | Per-job permissions: build reads, deploy writes packages only |
| Mutable action tags | `actions/checkout@v4` | SHA-pinned: `actions/checkout@11d5960a...` |
| Static credential | Long-lived `DEPLOY_KEY` | Guidance for OIDC short-lived federation |

## Defense layers

### Layer 1: least-privilege secret scoping

The build job declares no secrets at all — no `env:` block, no `${{ secrets.* }}` references. Even if a dependency is compromised during the build, there is nothing to exfiltrate.

The deploy job receives `DEPLOY_KEY` only in the step-level `env:` block of the deploy step itself. Other steps in the deploy job (artifact download, log audit) cannot access it.

```yaml
# Build job — zero secrets
build:
  permissions:
    contents: read
  steps:
    - name: Build
      run: echo "Building..."  # No DEPLOY_KEY in scope

# Deploy job — secret scoped to one step
deploy:
  steps:
    - name: Deploy
      env:
        DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}  # Only this step
      run: |
        # Use as opaque token — never echo
        curl -H "Authorization: Bearer $DEPLOY_KEY" ...
```

### Layer 2: environment protection

The deploy job runs in the `production` environment, which can be configured with:

- **Required reviewers** — a human must approve the deployment before secrets are released
- **Branch restrictions** — only the `main` branch can trigger deployments
- **Wait timer** — optional delay allowing manual abort before deployment begins

This prevents a compromised workflow from silently deploying or accessing secrets.

### Layer 3: no secrets in output

The hardened workflow never prints, echoes, or transforms the secret value. The `DEPLOY_KEY` is used as an opaque authentication token passed to the deployment tool (or verified for presence). A post-deployment step confirms no secret leakage occurred.

### Layer 4: per-job permissions

Instead of workflow-level `permissions:` (which applies to all jobs), each job declares only what it needs:

```yaml
build:
  permissions:
    contents: read        # Read source code only

deploy:
  permissions:
    contents: read        # Read artifacts
    packages: write       # Publish packages
    # id-token: write     # Uncomment for OIDC
```

### Layer 5: SHA-pinned actions

Every third-party action is pinned to a full commit SHA:

```yaml
uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4.4.0
```

This prevents mutable-tag hijack (CICD-SEC-3) — if an action's `v4` tag is force-pushed upstream, the SHA pin ensures the workflow continues using the known-good version.

### Layer 6: OIDC federation (guidance)

For production deployments, replace static secrets with OIDC-based short-lived credentials. GitHub Actions can exchange an OIDC token for cloud-provider credentials that expire in minutes:

```yaml
- name: Configure AWS credentials (OIDC)
  uses: aws-actions/configure-aws-credentials@<SHA>
  with:
    role-to-assume: arn:aws:iam::123456789012:role/deploy
    aws-region: us-east-1
    # No static key — token expires in 15 minutes
```

Short-lived credentials eliminate the entire class of "exfiltrated credential" attacks, because even if the token is captured, it becomes useless within minutes.

## Standards mapping

| Standard | Requirement | How the hardened workflow meets it |
|---|---|---|
| OWASP CICD-SEC-6 | Credential hygiene | Secrets scoped, not logged, environment-gated |
| OWASP CICD-SEC-5 | Least-privilege PBAC | Per-job permissions, read-only build |
| OWASP CICD-SEC-3 | Dependency integrity | All actions SHA-pinned |
| MITRE T1552 | Unsecured credentials | Secrets never exposed in logs or to unnecessary jobs |
| SLSA Build L2 | Tamper-resistant build | Hosted runner, locked permissions, no secrets in build |

## Deployment

1. Copy `deploy.yml` to `.github/workflows/deploy.yml` in the target repository.
2. Create a `production` environment in the repository settings:
   - Settings > Environments > New environment > `production`
   - Add at least one required reviewer
   - Restrict deployment branches to `main`
3. Set the `DEPLOY_KEY` secret at the repository or environment level.
4. (Recommended) Replace `DEPLOY_KEY` with OIDC federation for the target cloud provider.
5. Run the verification suite: `./verify/03-secret-exfil/verify.sh static`

## Verification

14 structural checks confirm the hardened workflow eliminates all exfiltration vectors. See `verify/03-secret-exfil/README.md`.
