# Detection — Scenario 10: GITHUB_TOKEN over-privilege

## Sigma rule

[`token-overprivilege.yml`](token-overprivilege.yml) fires on a workflow definition that grants `write-all`, grants a write scope at workflow level, or pairs a high-risk write scope with a trigger an outsider can fire.

## Scanner

[`detect.sh`](detect.sh) reports four vectors. Permission facts are extracted by [`perms.awk`](perms.awk), a small POSIX-awk parser shared with the attack simulation, so the scanner and the simulation can never disagree about what a workflow grants.

| Vector | What it catches |
|---|---|
| WRITE-ALL | `permissions: write-all` at workflow or job level |
| NO PERMISSIONS BLOCK | a job with no `permissions:` where the workflow sets none either, so the token takes the repository default |
| WORKFLOW-LEVEL WRITE | a write scope declared at workflow level, inherited by every job |
| WRITE ON UNTRUSTED TRIGGER | `write-all` or a high-risk write scope (`contents`, `actions`, `packages`, `id-token`, `deployments`, `pages`, `security-events`, `attestations`) reachable from `pull_request_target`, `issue_comment`, `issues`, `workflow_run` and similar |

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## False positives

| Source | Why it may be benign |
|---|---|
| A release job with `contents: write` on a pushed-tag trigger | Declared on the job, maintainer-only trigger: not flagged |
| A labeler on `pull_request_target` with `pull-requests: write` that never checks out PR code | Low-risk scope: not flagged |
| A workflow with no block in a repository whose default is already read-only | Flagged anyway: the default is a setting someone can change, the workflow should not depend on it |

## Limitations

- **Repository default is invisible to a file scan.** The scanner cannot see the Settings → Actions default, so it flags a missing block regardless. The runtime path could read it via `gh api repos/OWNER/REPO/actions/permissions/workflow`; that is not wired in.
- **Reusable-workflow callees.** A called workflow's own `permissions:` are bounded by the caller's grant; only the caller file is analysed here.
- **Parser scope.** `perms.awk` handles block and single-line flow mappings. A multi-line flow mapping or a YAML anchor is not expanded.
- **"High-risk" is a fixed list.** An application that treats `issues: write` as dangerous would need the list extended.
