# Hardened caller — Scenario 09: Reusable workflow trust boundary

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Reusable workflow ref | `@main` (mutable) | `@<40-char SHA>` with version comment |
| Secrets passed | `secrets: inherit` (all) | `NPM_TOKEN` only, by name |
| Upstream change | runs silently on next call | pin must change (reviewable) |
| Blast radius if callee compromised | every caller secret | one secret |

## The fix

### 1. Pin the reusable workflow by commit SHA

```yaml
uses: acme-shared/pipelines/.github/workflows/release.yml@3a9f1c2e… # v2.3.1
```

The ref is now immutable. The upstream owner cannot change what this call runs without the SHA changing, and a Dependabot PR surfaces any bump for review — the same guarantee scenario 04 gives actions, applied to reusable workflows.

### 2. Pass only the secrets the callee needs

```yaml
secrets:
  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Instead of `secrets: inherit` (which hands over everything), the caller passes exactly one secret by name. If the reusable workflow is ever compromised, it can reach `NPM_TOKEN` and nothing else — the caller's other credentials stay out of reach.

### 3. Prefer first-party reusable workflows

For anything that touches secrets, a reusable workflow you own and can review per-change is safer than one in another organization. When an external one is unavoidable, the SHA pin plus explicit secrets are the minimum bar.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-3 | Control dependency chains | Reusable workflow is immutable (SHA-pinned) |
| OWASP CICD-SEC-4 | Limit pipeline execution trust | Only the needed secret crosses the boundary |
| MITRE T1195.001 | Defend against dependency compromise | Upstream changes require a reviewed pin bump |

## Deployment

1. Replace the caller with `release.yml` from this directory.
2. Resolve the reusable workflow's current tag to its commit SHA and pin it (`lab pin` resolves action refs; resolve reusable-workflow refs the same way via `git ls-remote`).
3. Replace `secrets: inherit` with the explicit secrets the callee documents.
4. Verify: `./verify/09-reusable-workflow/verify.sh static` (7/7 checks).

## Verification

7 structural checks confirm the fix — scanner clears the hardened caller and flags the vulnerable one, the reusable workflow is pinned by a full SHA with a version comment, there is no mutable ref and no `secrets: inherit`, and any secrets passed are named explicitly.
