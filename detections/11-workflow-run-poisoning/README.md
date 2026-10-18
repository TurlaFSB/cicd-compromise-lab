# Detection — Scenario 11: workflow_run artifact poisoning

## Sigma rule

[`workflow-run-poisoning.yml`](workflow-run-poisoning.yml) fires on a `workflow_run`-triggered workflow definition that checks out the triggering head, interpolates untrusted `workflow_run` context into a shell, or downloads the triggering run's artifact **and** executes code from the workspace.

## Scanner

[`detect.sh`](detect.sh) only inspects `workflow_run`-triggered workflows — anything else is reported as out of scope and left clean. Structure facts are extracted by [`scan.awk`](scan.awk), which tells a `workflow_run:` trigger key apart from a `github.event.workflow_run` context reference, and a `run:` shell block apart from an `env:`/`with:` mapping.

| Vector | What it catches |
|---|---|
| UNTRUSTED WORKFLOW_RUN CONTEXT | an attacker-settable field (`head_branch`, `display_title`, `head_repository`, `head_commit`, `name`) interpolated into a `run:` shell block |
| CHECKOUT OF WORKFLOW_RUN HEAD | `actions/checkout` pinning `ref:` to `github.event.workflow_run.head_branch`/`head_sha`/`head_repository` |
| POISONED ARTIFACT EXECUTED | the handler downloads the triggering run's artifact (or checks out its head) **and** runs code from the workspace (`node`/`bash`/`sh`/`npm`/`source` on a path) |

An informational **NOTE** also prints whenever the handler downloads an artifact from the triggering run. Downloading is legitimate; it is not counted as a finding. It is there to remind the reviewer that those bytes are untrusted data and must be validated, never executed.

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## False positives

| Source | Why it may be benign |
|---|---|
| A `workflow_run` handler that downloads an artifact and only reads/validates it (never executes) | NOTE only, not a finding — this is the recommended pattern |
| Reading immutable `workflow_run` fields (`id`, `head_sha`, `conclusion`, `event`) for control flow | Not injectable; not matched |
| A `workflow_run` handler with no artifact download, no head checkout, and no untrusted context in a shell | Clean |

## Limitations

- **No cross-workflow reachability.** The scanner flags the privileged consumer by its own shape. It does not parse the *producer* to prove the upstream actually runs on fork PRs; a `workflow_run` handler that only ever follows a trusted `push` build is flagged the same way (treat it as a prompt to confirm the trigger).
- **Execution heuristic.** "Executes code" is a fixed list of interpreters and `npm`. A build step that runs attacker code through an unusual wrapper may be missed; a benign `node ./trusted.js` after a download is flagged (the download makes the tree untrusted).
- **Parser scope.** `scan.awk` is line-oriented. A `run:` body folded with unusual YAML block scalars, or context spread across a YAML anchor, is not expanded.
- **Data-flow is not tracked.** The scanner cannot tell a validated PR number from an unvalidated one; it keys on execution and context-in-shell, not on taint. Validation is checked structurally in `verify/`.
