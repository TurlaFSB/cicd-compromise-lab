# Hardened workflow — Scenario 06: Artifact tampering

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Build-time integrity | none | signed SLSA build-provenance attestation + SHA-256 manifest |
| Publish-time check | none (publishes downloaded bytes) | `gh attestation verify` + `sha256sum --check`, both before publish |
| Trust model | artifact store trusted blindly | published bytes cryptographically bound to the trusted build |
| Build permissions | `contents: read` | `contents: read`, `id-token: write`, `attestations: write` |
| Actions | SHA-pinned | SHA-pinned (incl. `attest-build-provenance`) |

## Defense layers

### 1. Build-provenance attestation (primary)

`actions/attest-build-provenance` generates a [SLSA](https://slsa.dev) build-provenance attestation over `dist/**`. The attestation is signed with a short-lived certificate bound to the build job's OIDC identity (Sigstore/Fulcio) and recorded in GitHub's attestation store and a public transparency log. It states, non-falsifiably, "this repo, this workflow, at this commit, produced exactly these bytes."

### 2. Verify before publish (the gate)

The publish job runs:

```bash
gh attestation verify "dist/" \
  --repo "$GITHUB_REPOSITORY" \
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"
```

before `npm publish`. If any byte changed between build and publish, verification fails and the job exits non-zero — nothing is shipped. This is the step the vulnerable version lacked. `--signer-workflow` pins *which* workflow's identity is acceptable, so an attestation minted by some other workflow in the repo is not accepted.

### 3. Checksum as a cheap second line

A SHA-256 manifest (`dist.sha256`) is generated at build time and re-checked with `sha256sum --check` before publish. It adds an offline integrity check that needs no network or OIDC, catching accidental corruption and simple tampering even if the attestation path is misconfigured.

### 4. Least privilege

`id-token: write` and `attestations: write` are scoped to the build job only (they are needed to mint and record the attestation). The publish job keeps `packages: write` plus `id-token: write` for verification. Permissions are declared per job, never at the workflow level.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-9 | Validate artifact integrity | Every published byte is attested at build and verified before publish |
| SLSA Build L3 | Non-falsifiable, platform-generated provenance | `attest-build-provenance` signs with the runner's OIDC identity; the consumer cannot forge it |
| MITRE T1195 | Defend the supply chain | The build-to-release hand-off is cryptographically bound end to end |

## Deployment

1. Replace the target repo's `release.yml` with the file here.
2. Ensure the repo can create attestations (public repos and GitHub-hosted runners support this out of the box).
3. Verify: `./verify/06-artifact-tampering/verify.sh static` (10/10 checks).
4. For consumers, document how to verify the published artifact themselves with `gh attestation verify`.

## Verification

10 structural checks confirm the fix — scanner clears the hardened workflow and flags the vulnerable one, the simulation reports SAFE vs. TAMPERABLE, and six structural invariants hold (attestation in build, verify-before-publish ordering, checksum generated and re-checked, `id-token`/`attestations` permissions on build, per-job permissions, SHA-pinned actions).
