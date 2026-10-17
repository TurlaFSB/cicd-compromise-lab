# Detection — Scenario 06: Artifact tampering

## Sigma rule

[`artifact-tampering.yml`](artifact-tampering.yml) fires on a workflow definition when an artifact crosses from producer to publisher with no integrity binding. Conditions:

| Condition | Meaning |
|---|---|
| download + publish, no verify | An artifact is downloaded and published with no attestation/signature/checksum verification between |
| upload, no provenance | An artifact is uploaded with no attestation, signature, or checksum |
| `workflow_run` + download | A privileged `workflow_run` job consumes artifacts from another (possibly untrusted) run |

## Scanner

[`detect.sh`](detect.sh) implements the rule as a job-aware scanner with three vectors:

| Vector | What it catches |
|---|---|
| UNVERIFIED PUBLISH | `download-artifact` (or `gh run download`) → publish (`npm publish`, `gh release`, `docker push`, …) with no `gh attestation verify` / `cosign verify` / `sha256sum --check` in between |
| NO PROVENANCE | `upload-artifact` with no `attest-build-provenance`, `cosign sign`, or generated checksum |
| CROSS-WORKFLOW CONSUMPTION | a `workflow_run`-triggered workflow that downloads artifacts |

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## Scan your own repos

```bash
for repo in $(gh repo list your-org --limit 100 --json nameWithOwner -q '.[].nameWithOwner'); do
  ./detect.sh runtime "$repo"
done
```

## False positives

| Source | Why it may be benign |
|---|---|
| Artifacts built and consumed only for testing, never published | No publish step → vector 1 does not fire, but vector 2 may; confirm nothing ships it |
| In-house verifier scripts not matched by the known patterns | The scanner looks for `gh attestation verify`, `cosign verify`, `slsa-verifier`, and `sha256sum -c`; a custom verifier is missed and reported as unverified |
| `workflow_run` consumer that only reads trusted same-repo producer artifacts and verifies them | Vector 3 is conservative by design; confirm the producer trust and the verification |

## Limitations

- **Pattern-based.** The scanner cannot confirm that a verification step actually covers the published bytes — only that a known verify command is present. A verify step that checks the wrong path would pass.
- **No dataflow.** It does not trace which artifact name flows into which publish step; it reasons at the workflow level.
- **Attestation coverage.** It does not confirm the attestation's `subject-path` matches what is published; the verification suite checks that for the lab's own hardened workflow, but the scanner does not enforce it on arbitrary repos.
