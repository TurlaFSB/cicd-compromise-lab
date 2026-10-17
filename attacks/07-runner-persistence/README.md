# Scenario 07 — Self-hosted runner persistence

**OWASP:** CICD-SEC-7 (Insecure System Configuration) · **MITRE ATT&CK:** T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution)

## Target

A CI workflow that runs untrusted `pull_request` code on a **self-hosted** runner (`runs-on: [self-hosted, linux, x64]`).

## The vulnerability

GitHub-hosted runners are fresh, single-use VMs destroyed after each job. Self-hosted runners are **not** — by default the same machine serves job after job. Anything a job leaves outside the workspace (a cron entry, a modified `~/.bashrc`, a user systemd unit, a background process, a tampered binary on `PATH`) is still there when the next job starts.

When a workflow runs untrusted `pull_request` code on such a runner, a fork PR author controls what that job does. They can drop a persistence implant that waits for a later, privileged job — a release, a deploy, a job with secrets — and then steals its `GITHUB_TOKEN` and secrets or tampers its build output. The attacker never merges anything; opening a PR is enough to get their code onto the runner.

### Why it is dangerous

| Factor | Impact |
|---|---|
| Reused machine | State survives between jobs, across workflows, and across repositories sharing the runner. |
| Untrusted trigger | A fork PR runs attacker code with no approval. |
| Cross-job theft | The implant waits for a privileged job and harvests its secrets — the untrusted job itself never needs them. |
| Hard to spot | Nothing in the privileged job's own definition looks wrong; the compromise lives on the host. |

## Simulation

`simulate.sh` models runner reuse offline:

```bash
./simulate.sh                                   # vulnerable ci.yml: PERSISTS (exit 1)
./simulate.sh ../../hardened/07-runner-persistence/ci.yml   # hardened: SAFE (exit 0)
```

Part 1 drops the benign implant (`payload/persist.sh`) into a runner "home" directory, then simulates the next job two ways: a **reused** runner (same home — implant still present) and an **ephemeral** runner (fresh home — implant gone). This shows ephemerality is what defeats persistence. Part 2 inspects the workflow: does an untrusted-trigger job run on a self-hosted runner? If so it reports PERSISTS.

## Payload

`payload/persist.sh` writes a benign `.lab-implant` marker into a persistent directory. A real implant would install a cron job, a user systemd unit, a shell-profile hook, or a background listener; the lab keeps it to a harmless, obvious marker.

## Fix direction

See `hardened/07-runner-persistence/`. Summary:

1. **Run untrusted code on GitHub-hosted runners** (`runs-on: ubuntu-latest`) — fresh VMs torn down after every job, so there is nothing to persist into.
2. **If self-hosted is required**, use **ephemeral** runners (registered with `--ephemeral`, one job per registration, auto-deregistered) in an isolated pool that never runs trusted jobs. This is a runner-side configuration, documented in the hardened README.
3. **Never share a runner pool** between untrusted-trigger workflows and privileged ones.
