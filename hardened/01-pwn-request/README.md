# Hardened workflow — scenario 01 (pwn request)

## Vulnerability recap

The original workflow (`.github/workflows/ci.yml` in `turla-lab-targets/pwn-request-target`) uses `pull_request_target` to check out and execute the PR author's code. Because `pull_request_target` runs with the base repo's `GITHUB_TOKEN` and secrets, any external contributor can run arbitrary code with write permissions and secret access simply by opening a PR — no approval, no review, no merge required.

## What changed

| Vulnerable pattern | Hardened pattern | Why |
|---|---|---|
| Single job on `pull_request_target` | Two jobs: `test` on `pull_request`, `label` on `pull_request_target` | Separates untrusted code execution from privileged operations |
| PR code checked out and run with secrets | PR code runs in `test` job with **no secrets, read-only token** | Untrusted code has no write permissions and no secret access |
| `pull_request_target` job checks out PR head | `label` job has **no checkout step** — only reads webhook metadata | Nothing for an attacker to inject; the privileged job never touches PR files |
| Actions pinned by mutable tag (`@v4`) | Actions pinned by full commit SHA | Prevents CICD-SEC-3 (mutable tag hijack) |
| `permissions` block allows `contents: read` + `pull-requests: write` in one job | Each job declares only the permissions it needs | Least privilege per CICD-SEC-5 |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  pull_request (from any contributor)                         │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Job: test                                               │ │
│  │ Token: read-only, scoped to the PR                      │ │
│  │ Secrets: NONE                                           │ │
│  │                                                         │ │
│  │  ✓ Checkout PR code                                     │ │
│  │  ✓ npm ci && npm test                                   │ │
│  │  ✗ Cannot post comments (no write token)                │ │
│  │  ✗ Cannot read DUMMY_CLOUD_KEY (not in env)             │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  pull_request_target (runs with base repo privileges)        │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Job: label                                              │ │
│  │ Token: write (pull-requests only)                       │ │
│  │ Secrets: available but unused                           │ │
│  │                                                         │ │
│  │  ✗ Does NOT checkout any code                           │ │
│  │  ✗ Does NOT run npm test                                │ │
│  │  ✓ Posts a status comment using trusted event metadata   │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Standards mapping

| Control | Standard | Status |
|---|---|---|
| No untrusted code runs with secrets | OWASP CICD-SEC-4 (Poisoned Pipeline Execution) | ✅ Eliminated |
| Least-privilege `permissions:` per job | OWASP CICD-SEC-5 (Insufficient PBAC) | ✅ Applied |
| Actions pinned to commit SHA | OWASP CICD-SEC-3 (Dependency Chain Abuse) | ✅ Applied |
| Ephemeral hosted runner, no persistent state | OWASP CICD-SEC-7 (Insecure System Configuration) | ✅ Default (GitHub-hosted) |
| Build runs on hosted infra with locked-down perms | SLSA Build L2 | ✅ Met |
| Supply chain compromise via PR mitigated | MITRE ATT&CK T1195 | ✅ Mitigated |

## Deployment

To apply this fix to the target repo:

1. Replace `.github/workflows/ci.yml` in `turla-lab-targets/pwn-request-target` with this file.
2. Verify the SHA pins match the action versions you intend to use (run `git ls-remote --tags https://github.com/actions/checkout` to check).
3. Remove `DUMMY_CLOUD_KEY` from the workflow env entirely — the test job should not need any secret.

## Why not an environment gate instead?

An alternative fix is to keep `pull_request_target` for everything but gate it behind a GitHub environment with required reviewers. This works, but it relies on humans not rubber-stamping reviews. The split-job approach is structurally safe — there is no combination of human error that re-introduces the vulnerability, because the untrusted job simply cannot access secrets.

For high-security repos, both controls together (split jobs **and** environment protection on the privileged job) provide defense in depth.
