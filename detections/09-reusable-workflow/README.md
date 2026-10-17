# Detection — Scenario 09: Reusable workflow trust boundary

## Sigma rule

[`reusable-workflow.yml`](reusable-workflow.yml) fires when a caller invokes a reusable workflow by a mutable ref, or passes `secrets: inherit`.

## Scanner

[`detect.sh`](detect.sh) distinguishes a **job-level** `uses:` (a reusable-workflow call) from a **step-level** `- uses:` (an action), and reports:

| Vector | What it catches |
|---|---|
| REUSABLE BY MUTABLE REF | a reusable workflow pinned to `@main`/`@v1`/any non-SHA ref |
| SECRETS INHERIT | a call that passes `secrets: inherit` |
| EXTERNAL + INHERIT | a reusable workflow that receives `secrets: inherit` (all caller secrets cross the boundary) |

Local reusable workflows (`./.github/workflows/x.yml`) are same-repo and are not flagged.

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## False positives

| Source | Why it may be benign |
|---|---|
| Local reusable workflow (`./…`) | Same repo, no external ref to hijack; not flagged |
| First-party reusable workflow pinned by SHA | Safe; still prefer explicit secrets over inherit |
| A trusted org-internal workflow that needs several secrets | Pass them by name; `secrets: inherit` is still flagged because it is broader than necessary |

## Limitations

- **Owner comparison is coarse.** The scanner flags any `secrets: inherit` on a reusable-workflow call; it does not parse the caller's own `owner/repo` to prove the callee is external. In practice `inherit` is over-broad even same-org, so this errs toward flagging.
- **Input-based secrets.** Secrets smuggled as plain `with:` inputs rather than the `secrets:` block are not evaluated here.
