# Hardened workflows — Scenario 11: workflow_run artifact poisoning

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Artifact uploaded by the producer | the whole checked-out tree (`path: .`) | one file, the PR number (`NR`) |
| Head checkout in the consumer | `ref: ${{ github.event.workflow_run.head_branch }}` | none — the fork's code is never checked out |
| Artifact use | `node ./scripts/comment.js` (executed) | read, validated as `[0-9]+`, never executed |
| `workflow_run` context in a shell | `echo "... ${{ ...head_branch }}"` | only `event` is read, via `if:`, for control flow |
| Permissions | `contents: write` + `pull-requests: write` at workflow level | `contents: read` floor; `pull-requests: write` on the one job |
| Trigger guard | `conclusion == 'success'` only | also `event == 'pull_request'` |

## Why each change works

### 1. The producer uploads data, not a tree

```yaml
- name: Record PR number
  run: echo "${{ github.event.number }}" > NR
- uses: actions/upload-artifact@... # v4.6.2
  with:
    name: pr-number
    path: NR
```

The consumer needs exactly one thing from the untrusted build: which PR to comment on. Uploading only that removes the fork's scripts from the artifact entirely — there is nothing executable for a downstream job to run.

### 2. The consumer treats the artifact as untrusted data

```yaml
- name: Validate PR number
  id: pr
  run: |
    set -euo pipefail
    num="$(tr -dc '0-9' < pr-number/NR | head -c 12)"
    [ -n "$num" ] || { echo "no valid PR number" >&2; exit 1; }
    echo "number=$num" >> "$GITHUB_OUTPUT"
```

A fork can still write anything into `NR`, so the value is sanitised to digits and length-capped before use. It is read, never executed. Nothing from the artifact ever reaches a shell as code.

### 3. No head checkout, no untrusted context in a shell

The hardened consumer never runs `actions/checkout` against the triggering head, so fork code is never materialised in the privileged job. The one `workflow_run` field it consults — `event` — is used only in the job `if:` for control flow, not spliced into a command.

### 4. Least privilege

```yaml
permissions:
  contents: read          # workflow floor
jobs:
  comment:
    permissions:
      pull-requests: write # the only write scope commenting needs
```

Even if something slipped through, the token can comment on a PR and nothing more — no `contents: write`, no package or release access.

## Residual risk

The consumer still downloads an artifact produced by an untrusted run, so the download itself is retained (the scanner emits a NOTE, not a finding). The protection is that the bytes are validated and never executed. If future changes need more than a PR number from the upstream, each new field must be validated the same way — treat the artifact boundary as a parser, not a trust boundary.
