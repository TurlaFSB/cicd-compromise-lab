# Hardened workflow — Scenario 04: Mutable action tag hijack

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Action references | `@v4`, `@v1`, `@v2` (11 mutable tags) | `@<40-char SHA>` with tag in comment (11 pinned) |
| Permissions | Workflow-level `contents: write`, `packages: write` | Per-job least-privilege (`contents: read`) |
| Secret scope | Workflow-level `env:` block (all jobs have access) | Step-level `env:` in deploy job only |
| Checkout credentials | Default (token persists in Git config) | `persist-credentials: false` on every checkout |
| Environment protection | None | `environment: production` with required reviewers |
| Update mechanism | Manual tag bumps (if anyone remembers) | Dependabot opens PRs with SHA diffs for review |

## Defense layers

### 1. SHA pinning

Every `uses:` line references a full 40-character commit SHA — an immutable, content-addressed identifier that cannot be force-pushed or retagged:

```yaml
# BEFORE (vulnerable):
- uses: actions/checkout@v4

# AFTER (hardened):
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

The human-readable tag is preserved in a trailing comment for auditability. If the upstream action is compromised and the tag repointed, the workflow continues running the code at the pinned SHA — the attack has no effect.

### 2. Dependabot for automated SHA updates

The repo's `.github/dependabot.yml` includes:

```yaml
- package-ecosystem: github-actions
  directory: /
  schedule:
    interval: weekly
```

When an action publishes a new release, Dependabot opens a pull request that shows the exact diff between the old and new SHA. A human reviews the change before merging — no more silent upgrades.

### 3. Per-job least-privilege permissions

The vulnerable workflow granted `contents: write` and `packages: write` at the workflow level, giving every job those permissions even when they only needed read access. The hardened version:

- **lint, test, build**: `contents: read` only
- **deploy**: `contents: read` (no write needed for deployment via external action)
- No job has more permissions than it needs

### 4. Step-scoped secrets

The vulnerable workflow placed `DEPLOY_TOKEN` and `NPM_TOKEN` in a workflow-level `env:` block, making them accessible to every step in every job — including the compromised action. The hardened version restricts secrets to the specific step's `env:` block.

### 5. `persist-credentials: false`

Every `actions/checkout` step sets `persist-credentials: false`, preventing the `GITHUB_TOKEN` from being stored in the cloned repo's Git configuration. Without this, a compromised action that runs after checkout could read the token from `.git/config`.

### 6. Environment protection

The deploy job uses `environment: production`, which can be configured with:
- Required reviewers before the job runs
- Branch restrictions (only `main` can deploy)
- Wait timers

This adds a human gate before any secret-consuming job executes.

## Standards mapping

| Standard | Requirement | How this workflow meets it |
|---|---|---|
| **OWASP CICD-SEC-3** | Prevent dependency chain abuse | All actions SHA-pinned; Dependabot for managed updates |
| **SLSA Build L2** | Hermetic, version-locked dependencies | Every dependency is content-addressed (SHA) |
| **MITRE T1195.001** | Defend against software dependency compromise | Mutable tags eliminated; update path requires human review |
| **GitHub Security Hardening** | Pin actions to full-length commit SHA | All 11 action references use 40-char SHAs |

## Deployment

1. Replace the target repo's workflow with `ci.yml` from this directory.
2. Ensure `.github/dependabot.yml` includes the `github-actions` ecosystem.
3. Configure a `production` environment in repo settings:
   - Settings > Environments > New environment > `production`
   - Add at least one required reviewer
   - Restrict to `main` branch
4. Verify: `./verify/04-tag-hijack/verify.sh static` (12/12 checks should pass).
5. Optionally run `zizmor` or `actionlint` as a CI gate to prevent future regressions.

## Verification

12 structural checks confirm the fix:

| # | Check | Status |
|---|---|---|
| 1 | Detection scanner clears hardened workflow | PASS |
| 2 | Detection scanner flags vulnerable workflow | PASS |
| 3a | All 11 uses: lines pinned by 40-char SHA | PASS |
| 3b | No mutable version tags (@vN) | PASS |
| 3c | No mutable branch refs (@main, @master) | PASS |
| 3d | Every SHA has a version comment | PASS |
| 3e | Permissions are per-job, not workflow-level | PASS |
| 3f | No secrets in workflow-level env: block | PASS |
| 3g | All checkouts use persist-credentials: false | PASS |
| 3h | All 4 jobs declare their own permissions | PASS |
| 3i | Deploy job uses environment: protection | PASS |
| 3j | No contents: write in any job | PASS |
