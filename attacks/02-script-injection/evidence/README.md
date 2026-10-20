# Scenario 02 evidence — live script injection

**Target:** [`turla-lab-targets/script-injection-target`](https://github.com/turla-lab-targets/script-injection-target) (dummy lab target, no real secrets)
**Trigger issue:** [#1](https://github.com/turla-lab-targets/script-injection-target/issues/1)
**Run:** [39404529625](https://github.com/turla-lab-targets/script-injection-target/actions/runs/39404529625) — `issues` event, conclusion `success`
**Date:** 2026-10-20

## What was done

An issue was opened whose **title** was:

```
Edge case in add() for large inputs $(id -un)-RCEPROOF-S02
```

The vulnerable workflow (`.github/workflows/triage.yml`) interpolates
`${{ github.event.issue.title }}` directly into a `run:` step.

## Proof of code execution

GitHub Actions substitutes `${{ }}` as a literal string into the generated
shell script *before* bash runs. The generated script line was:

```bash
echo "Thanks for opening: Edge case in add() for large inputs $(id -un)-RCEPROOF-S02"
```

and the executed output (see `triage-step.log.txt`) was:

```
Thanks for opening: Edge case in add() for large inputs runner-RCEPROOF-S02
```

`$(id -un)` **executed** and resolved to the runner user `runner`. If the
title had been treated as inert data (as in the hardened workflow, which
passes it via `env:`), the log would show the literal `$(id -un)` string.

## Blast radius captured in the log

The run's `GITHUB_TOKEN` carried `Contents: read`, `Issues: write`,
`Metadata: read`. Any command injected through the title runs with that
token and with any secret placed in the step's `env:` — i.e. arbitrary code
execution in the pipeline, triggered by anyone who can open an issue.

## Files

- `run-metadata.json` — the workflow run object and triage job metadata.
- `triage-step.log.txt` — the relevant log excerpt (generated script + executed output).

## Reproduce

See `../README.md`. The command-substitution marker is benign (`id -un`); no
secret is read or exfiltrated. The hardened workflow in
`hardened/02-script-injection/triage.yml` prints the title literally instead
of executing it.
