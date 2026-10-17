# Hardened workflow — Scenario 07: Self-hosted runner persistence

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Runner for untrusted code | `self-hosted` (reused) | `ubuntu-latest` (ephemeral, GitHub-hosted) |
| State between jobs | survives on the host | discarded with the VM |
| Fork-PR reachability | implant persists into later jobs | nothing persists |

## The fix

### 1. GitHub-hosted runners for untrusted code (primary)

`runs-on: ubuntu-latest` gives every job a fresh, single-use VM that is destroyed when the job ends. A fork PR's job cannot leave anything behind for a later job, because there is no "later job" on the same machine — the machine is gone.

### 2. If self-hosted is unavoidable: make it ephemeral

Some workloads need self-hosted runners (special hardware, private-network access). The safe configuration is a runner-side setting, not a workflow one:

- Register the runner with `./config.sh --ephemeral`, so it accepts exactly one job and then deregisters.
- Run them behind an autoscaler (e.g. actions-runner-controller) that provisions a fresh runner per job.
- Keep untrusted-trigger workflows in an **isolated pool** that never runs trusted jobs, so even a single-job compromise cannot reach a privileged workload.

Because ephemerality is not expressible in workflow YAML, the workflow's own obligation is simply to keep untrusted triggers off persistent runners — which this hardened version does by using a GitHub-hosted runner.

### 3. Least privilege retained

The job keeps `permissions: contents: read` and SHA-pinned actions, so even within its own run it has no more access than it needs.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-7 | Secure runner/system configuration | Untrusted code runs only on ephemeral runners |
| MITRE T1053 / T1547 | Deny persistence footholds | No reused host for an implant to survive on |

## Deployment

1. Replace the target repo's PR workflow with `ci.yml` from this directory.
2. If you must keep self-hosted runners, re-register them as ephemeral and isolate the pool as above.
3. Verify: `./verify/07-runner-persistence/verify.sh static` (9/9 checks).

## Verification

9 structural checks confirm the fix — scanner clears the hardened workflow and flags the vulnerable one, the simulation reports SAFE vs. PERSISTS, and the workflow uses a GitHub-hosted runner with no self-hosted label, no persistence-writing step, read-only permissions, and SHA-pinned actions.
