# Detection — Scenario 13: credential leakage via artifacts

## Sigma rule

[`artifact-cred-leak.yml`](artifact-cred-leak.yml) fires on a workflow definition that writes a secret to a file, or uploads an artifact with a broad path or `include-hidden-files: true`.

## Scanner

[`detect.sh`](detect.sh) reports four vectors. Step structure is parsed by [`leak.awk`](leak.awk), which tracks step boundaries so a `path:` or `persist-credentials:` input is only read inside the step it belongs to (an upload or a checkout), not confused with an identically named input on another action.

| Vector | What it catches |
|---|---|
| PERSISTED CHECKOUT CREDENTIAL | `actions/checkout` without `persist-credentials: false`, in a job that also uploads an artifact |
| SECRET WRITTEN TO FILE | a `run:` step redirecting `${{ secrets.* }}` into a file (`>`, `>>`, `tee`) — excluding `$GITHUB_*` runner files |
| BROAD ARTIFACT PATH | `upload-artifact` path of `.`, the workspace, `*`, or `**` |
| HIDDEN FILES IN ARTIFACT | `upload-artifact` with `include-hidden-files: true` |

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## False positives

| Source | Why it may be benign |
|---|---|
| `persist-credentials` left default in a job that never uploads an artifact | Not flagged — vector 1 requires an upload in the same file |
| A secret redirected into `$GITHUB_ENV` / `$GITHUB_OUTPUT` | Excluded — that is scenario 08's concern, not an artifact leak |
| `path: dist/` or another specific directory | Narrow path, not flagged |

## Limitations

- **File-level, not job-level, for vector 1.** The scanner pairs a persisted checkout with an upload anywhere in the same file, not strictly the same job. A workflow that checks out in one job and uploads in another unrelated job is flagged conservatively.
- **No taint tracking.** It cannot prove a written secret is the exact file later uploaded; it flags the write and the broad upload independently.
- **Path heuristic.** "Broad" is a fixed set (`.`, workspace, `*`, `**`). A path like `./src/..` that resolves to the root, or a matrix-expanded path, is not normalised.
- **Parser scope.** `leak.awk` is line-oriented; a step whose inputs come from a YAML anchor or an unusual block style may not be fully tracked.
