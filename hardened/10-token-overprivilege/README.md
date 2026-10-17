# Hardened workflows — Scenario 10: GITHUB_TOKEN over-privilege

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| `ci.yml` token | `write-all`, on `pull_request_target` | `contents: read` floor, on `pull_request` |
| `labeler.yml` token | repository default (unknown) | `{}` floor, `pull-requests: write` on the one job |
| `triage.yml` token | contents + packages + id-token write on `issue_comment` | `{}` floor, `issues: write` on the one job |
| Release write access | n/a | `contents: write` on the `publish` job only, maintainer-only tag trigger |
| Checkout credentials | persisted in `.git/config` | `persist-credentials: false` |

## Why each change works

### 1. A read-only floor at workflow level

```yaml
permissions:
  contents: read
```

Every job inherits the floor, so a job added later cannot silently gain write access. `permissions: {}` goes further and removes even read access, which suits workflows that call only the API with their own scoped credentials.

### 2. Write scopes on the job, not the workflow

```yaml
jobs:
  publish:
    permissions:
      contents: write   # create the GitHub release; scoped to this job only
```

A reviewer reading the job sees the grant beside the step that needs it. The `build` job in the same file stays read-only, so a compromised build step cannot publish.

### 3. No high-risk write behind an untrusted trigger

The triage bot only posts an acknowledgement, so it holds `issues: write` and nothing else. Even if its steps were hijacked through the comment text, the token cannot push code, publish a package, or request a cloud identity.

### 4. `pull_request`, not `pull_request_target`, for CI

CI that builds PR code has no business holding repository authority. `pull_request` gives forks a read-only token with no secrets.

### 5. Fail safe at the repository level

Set **Settings → Actions → General → Workflow permissions** to *Read repository contents and packages permissions* (and the same at organisation level). Workflows then fall back to read-only if someone forgets a block.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-5 | Least privilege for pipelines | Read-only floor, narrow per-job grants |
| OWASP CICD-SEC-6 | Credential hygiene | Credentials not persisted by checkout; no ambient write token |
| MITRE T1078.004 | Limit cloud-account abuse | `id-token: write` removed from untrusted paths |
| SLSA | Isolated, least-privilege build | Build job read-only; publish job separate |

## Deployment

1. Copy each hardened workflow over its vulnerable counterpart.
2. For every other workflow in your repository, add `permissions: contents: read` (or `{}`) at the top level, then add job-level grants until the run passes.
3. Set the repository and organisation default to read-only.
4. Verify: `./verify/10-token-overprivilege/verify.sh static` (15 checks).

## Verification

15 checks: the scanner clears the hardened set and flags the vulnerable set, all four vectors fire, a low-risk write is not over-flagged, the simulation condemns the vulnerable set and clears the hardened one, and structural invariants hold (floor present, no `write-all`, no `pull_request_target` CI, SHA-pinned actions, write scopes at job level only).
