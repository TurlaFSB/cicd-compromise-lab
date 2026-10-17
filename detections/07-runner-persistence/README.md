# Detection — Scenario 07: Self-hosted runner persistence

## Sigma rule

[`runner-persistence.yml`](runner-persistence.yml) fires when a workflow runs untrusted code on a self-hosted runner, or writes to a persistence location on one:

| Condition | Meaning |
|---|---|
| untrusted trigger + self-hosted | `pull_request(_target)` code runs on a `self-hosted` runner |
| self-hosted + persistence write | a step touches crontab, shell profiles, user systemd, or autostart |

## Scanner

[`detect.sh`](detect.sh) is job-aware and reports three vectors:

| Vector | What it catches |
|---|---|
| UNTRUSTED ON SELF-HOSTED | a `pull_request(_target)` workflow with a `runs-on: self-hosted` (or non-hosted custom label) job |
| SELF-HOSTED + PR CODE | that job also checks out and runs PR-controlled code (`npm ci/test`, `make`, `bash`, …) |
| PERSISTENCE-WRITING STEP | a non-comment step writes to crontab, `~/.bashrc`/`~/.profile`, user systemd, `/etc/profile.d`, or autostart |

A `runs-on` label that is not a known GitHub-hosted prefix (`ubuntu-`, `windows-`, `macos-`) is treated as self-hosted.

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

## False positives

| Source | Why it may be benign |
|---|---|
| Ephemeral self-hosted runners (`--ephemeral`) | Each runner serves one job then deregisters; nothing persists. Ephemerality is a runner-side setting invisible to the workflow, so confirm it out of band. |
| Isolated self-hosted pools that never run untrusted triggers | The untrusted path is what makes persistence reachable. |
| A self-hosted job on a trusted trigger only (push to main) | Still worth hardening, but not externally reachable via a fork PR. |

## Limitations

- **Ephemerality is invisible in YAML.** The scanner cannot tell an ephemeral self-hosted runner from a persistent one; it flags the untrusted-on-self-hosted combination and leaves the ephemerality check to the operator.
- **Custom-label heuristic.** Any `runs-on` label that is not an `ubuntu-/windows-/macos-` prefix is treated as self-hosted. A repo using a GitHub-hosted larger-runner group with a custom label would be flagged; confirm the label's backing.
