# Scenario 09 — Reusable workflow trust boundary

**OWASP:** CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-4 (Poisoned Pipeline Execution) · **MITRE ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)

## Target

A release caller that delegates to a reusable workflow in another organization:

```yaml
jobs:
  release:
    uses: acme-shared/pipelines/.github/workflows/release.yml@main
    secrets: inherit
```

## The vulnerability

A reusable workflow is called with a **job-level `uses:`** and runs with whatever inputs and secrets the caller passes. Two choices here each open a trust-boundary hole, and together they are severe:

1. **Mutable ref (`@main`).** The ref is resolved at call time. The owner of `acme-shared/pipelines` — or anyone who compromises that repo — can change `release.yml` on `main`, and the next release here silently runs the new code. This is the reusable-workflow form of the mutable-tag hijack in scenario 04.

2. **`secrets: inherit`.** This passes **every** secret the caller holds to the callee, not just the one it needs. If the reusable workflow is malicious or compromised, it receives `NPM_TOKEN`, `DEPLOY_KEY`, cloud credentials — the lot — in a single call.

Combined, an external party controls code that runs with all of the caller's secrets, and can change that code at any time without the caller noticing.

## Why it is dangerous

| Factor | Impact |
|---|---|
| Cross-org trust | The caller trusts code it does not own and cannot review per-run. |
| Mutable ref | No pin, no diff, no approval — upstream changes propagate on the next call. |
| `secrets: inherit` | Blast radius is every secret, not the minimum needed. |

## Detection

This is a structural issue (like scenario 04), so there is no runtime simulation — the scanner proves it directly. Against the vulnerable caller it reports both the mutable ref and the external-`inherit` combination; against the hardened caller it reports nothing.

## Fix direction

See `hardened/09-reusable-workflow/`. Summary:

1. **Pin the reusable workflow to a full commit SHA** (version in a trailing comment), so upstream cannot change what runs; let Dependabot bump it with review.
2. **Pass only the secrets the callee needs, by name** (`secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`), never `secrets: inherit`.
3. Prefer first-party or vendored reusable workflows for anything that handles secrets.
