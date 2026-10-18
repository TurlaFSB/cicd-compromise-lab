# Scenario 12 — OIDC trust policy misconfiguration

**OWASP:** CICD-SEC-5 (Insufficient PBAC), CICD-SEC-2 (Inadequate IAM) · **MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)

## Target

This scenario spans both sides of the OIDC exchange:

| File | Side | Flaw |
|---|---|---|
| `trust-policy.json` | cloud (AWS IAM) | `sub` condition is `repo:turla-lab-targets/*` (any repo in the org, any ref) and there is no `aud` condition |
| `deploy.yml` | GitHub (workflow) | `id-token: write` at workflow level, on a `pull_request_target` trigger a fork PR can reach |

## The vulnerability

OIDC replaces long-lived cloud keys in CI with a short-lived, GitHub-signed token. A workflow with `id-token: write` asks GitHub for a JWT whose `sub` claim describes the run (`repo:ORG/REPO:ref:refs/heads/main`, or `:environment:production`, etc.) and whose `aud` claim is the intended audience. The cloud provider's **trust policy** decides which of those tokens may assume a role. The security of the whole exchange lives in that policy's conditions — and in who can cause a matching token to be minted.

Both halves are misconfigured here:

- **Cloud side.** The trust policy uses `StringLike` with `repo:turla-lab-targets/*`. In an IAM condition `*` matches any characters, so this admits *every* repository in the org, on *any* branch, tag, PR, or environment. It also sets no `aud` condition, so a token minted for a different audience is accepted too. A single over-broad role becomes assumable by anything the org can run.
- **GitHub side.** `deploy.yml` grants `id-token: write` to the whole workflow and runs on `pull_request_target`. That trigger executes in the base-repo context and is reachable by fork pull requests, so an attacker who lands an injected step (see scenarios 02, 08, 11) can mint an OIDC token and exchange it for the role's credentials — no merge required.

## Attack path

1. Attacker opens (or influences) a run in any repo the org controls — or a fork PR against this workflow.
2. The run mints a GitHub OIDC token; its `sub` matches `repo:turla-lab-targets/*`.
3. `aws-actions/configure-aws-credentials` exchanges it with AWS STS. The trust policy's wildcard admits the token.
4. The run receives real credentials for `role/lab-preview-deploy` and acts in the cloud account.

## Simulation

[`simulate.sh`](simulate.sh) models the STS decision offline — no AWS account needed:

```bash
./simulate.sh                      # judge the vulnerable trust-policy.json
./simulate.sh <trust-policy.json>  # judge a specific policy
```

It evaluates four example token subjects (the intended repo+ref, another branch, another repo in the org, an unrelated attacker repo) against the policy's `sub`/`aud` conditions and prints which are admitted, then declares the policy `EXPLOITABLE` (exit 1) if it admits anything beyond the one intended identity or leaves the audience unconstrained, else `SAFE` (exit 0).

## Fix direction

See `hardened/12-oidc-trust-policy/`. Summary:

1. Pin the trust policy's `sub` to one repo **and** one ref/environment with `StringEquals`; never a wildcard.
2. Add a `StringEquals` `aud` condition (`sts.amazonaws.com` for AWS).
3. Grant `id-token: write` on the single job that assumes the role, under a read-only workflow floor.
4. Run cloud-touching deploys only from trusted triggers (push to a protected branch, a tag, or a protected environment) — never `pull_request_target`.
