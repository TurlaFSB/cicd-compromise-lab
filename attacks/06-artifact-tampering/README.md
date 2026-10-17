# Scenario 06 — Artifact tampering

**OWASP:** CICD-SEC-9 (Improper Artifact Integrity Validation) · **MITRE ATT&CK:** T1195 (Supply Chain Compromise)

## Target

A release pipeline with two jobs: `build` produces `dist/` and uploads it as a workflow artifact; `publish` downloads `dist/` and runs `npm publish`.

## The vulnerability

`actions/upload-artifact` and `actions/download-artifact` carry **no integrity guarantee**. The artifact store holds whatever bytes were uploaded, and the consumer trusts them blindly. In the vulnerable `release.yml`:

- The build job uploads `dist/` with no signature, no SLSA provenance attestation, and no checksum.
- The publish job downloads `dist/` and publishes it directly.

Nothing cryptographically binds *what the build produced* to *what the publish job shipped*. If anything can write the artifact between the two jobs, the publish job ships the tampered bytes to every downstream consumer.

### Who can tamper

| Actor | How |
|---|---|
| A compromised intermediate step | Any step between build and publish (a linter, a notifier) that runs attacker-influenced code can overwrite `dist/`. |
| A malicious or shared self-hosted runner | Residual access to the workspace or artifact cache. |
| A second workflow with artifact write access | Artifacts are scoped to the repo; another workflow run can overwrite an artifact of the same name. |
| A fork's producing run (workflow_run variant) | When a privileged `workflow_run` workflow downloads artifacts from the triggering run, that run may be an untrusted fork PR. |

### Why it is dangerous

The published package is what users install. A tampered `dist/` can carry a malicious `postinstall` script or a backdoored bundle, and because it ships under the project's real name and version, downstream consumers have no signal that anything changed. This is the Codecov / SolarWinds shape: compromise the build-to-release hand-off, not the source.

## Simulation

Because the attack is about bytes changing between jobs rather than log output, `simulate.sh` demonstrates the mechanism concretely and then judges a workflow:

```bash
./simulate.sh                                   # vulnerable release.yml: TAMPERABLE (exit 1)
./simulate.sh ../../hardened/06-artifact-tampering/release.yml   # hardened: SAFE (exit 0)
```

Part 1 builds a fake artifact, records its SHA-256 (standing in for a signed provenance attestation), tampers it with `payload/tamper.sh`, and shows that a **verifying** consumer rejects the tampered bytes while a **blind** consumer ships them. Part 2 inspects the workflow for an integrity binding — a producer that attests/signs/checksums *and* a consumer that verifies before publishing — and reports SAFE or TAMPERABLE.

## Payload

`payload/tamper.sh` is a benign stand-in: it appends a visible marker line to the artifact. A real tamper would inject a malicious `postinstall` or replace the bundle; the lab keeps it harmless and obvious.

## Fix direction

See `hardened/06-artifact-tampering/`. Summary:

1. **Attest at build time**: `actions/attest-build-provenance` generates a signed SLSA build-provenance attestation over `dist/`, tied to the repo, workflow, and commit via the job's OIDC identity and recorded in a public transparency log.
2. **Verify before publish**: `gh attestation verify` runs against the downloaded artifact before `npm publish`; a single changed byte fails verification and aborts the job.
3. **Checksum as a cheap second check**: a SHA-256 manifest is generated at build and re-checked (`sha256sum --check`) before publish.
4. **Least privilege**: `id-token: write` and `attestations: write` are granted only to the build job; publish keeps `packages: write`.
