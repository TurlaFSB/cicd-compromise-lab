# Hardened configuration — Scenario 12: OIDC trust policy misconfiguration

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Trust policy `sub` | `StringLike` `repo:turla-lab-targets/*` (any repo, any ref) | `StringEquals` `repo:turla-lab-targets/oidc-trust-target:ref:refs/heads/main` |
| Trust policy `aud` | absent | `StringEquals` `sts.amazonaws.com` |
| Workflow `id-token` | `write` at workflow level | `write` on the one deploy job, read-only floor |
| Trigger | `pull_request_target` (fork-reachable) | `push` to `main` (trusted) |
| AWS audience input | default | `audience: sts.amazonaws.com`, matching the policy |

## Why each change works

### 1. Pin the subject to one identity (cloud side)

```json
"StringEquals": {
  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
  "token.actions.githubusercontent.com:sub": "repo:turla-lab-targets/oidc-trust-target:ref:refs/heads/main"
}
```

`StringEquals` requires an exact match, so only a token from this repo, on this ref, is admitted. A token from another repo in the org, another branch, or a fork PR no longer matches. Switching from `StringLike` to `StringEquals` is the single most important change — a `*` in a trust condition is almost always a mistake.

Other valid subject forms, depending on how the deploy is gated:
- `repo:ORG/REPO:ref:refs/heads/main` — a specific branch
- `repo:ORG/REPO:environment:production` — a protected environment (recommended for production; environment protection rules then gate the deploy)
- `repo:ORG/REPO:ref:refs/tags/v*` — tag releases (note the trailing wildcard still widens to any tag)

### 2. Constrain the audience (cloud side)

Adding the `:aud` condition means a token minted for a different audience cannot be replayed against this role. The workflow sets `audience: sts.amazonaws.com` so the two agree.

### 3. Least-privilege token minting (GitHub side)

```yaml
permissions:
  contents: read          # workflow floor
jobs:
  deploy:
    permissions:
      id-token: write      # only this job may mint an OIDC token
```

A job added later cannot silently gain token-minting ability, and no job other than `deploy` can mint one at all.

### 4. Trusted trigger only (GitHub side)

Running on `push` to `main` removes the fork-reachable path entirely. There is no untrusted run that could mint a token, so even a momentarily over-broad policy has no attacker-reachable client. For production, prefer a protected **environment** with required reviewers and scope the trust policy's `sub` to `:environment:production`.

## Defense in depth

The two fixes are independent and both matter. Pinning the trust policy stops an unintended identity from assuming the role even if a workflow over-grants `id-token`. Scoping the workflow and its trigger stops an attacker from minting a matching token in the first place. Ship both.

## Standards

- OWASP CICD-SEC-5 (Insufficient PBAC), CICD-SEC-2 (Inadequate IAM)
- GitHub: *Security hardening your deployments with OpenID Connect*
- AWS: *Configuring OpenID Connect in Amazon Web Services* (recommends scoping the trust policy's `sub` and setting `aud`)
