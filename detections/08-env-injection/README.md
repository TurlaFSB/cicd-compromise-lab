# Detection — Scenario 08: GITHUB_ENV / GITHUB_PATH injection

## Sigma rule

[`env-injection.yml`](env-injection.yml) fires when a workflow writes to a runner environment file (`$GITHUB_ENV` / `$GITHUB_PATH`) **and** that write carries untrusted context or sets an execution-hijacking variable.

## Scanner

[`detect.sh`](detect.sh) reports three vectors:

| Vector | What it catches |
|---|---|
| UNTRUSTED TO GITHUB_ENV | `${{ github.event.* }}` / `github.head_ref` written to `$GITHUB_ENV` |
| UNTRUSTED TO GITHUB_PATH | the same untrusted context appended to `$GITHUB_PATH` |
| DANGEROUS VAR TO GITHUB_ENV | an execution-hijacking variable (`NODE_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `PYTHONPATH`, `PERL5LIB`, `DYLD_INSERT_LIBRARIES`) set via `$GITHUB_ENV` |

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error. Comment lines are ignored.

## False positives

| Source | Why it may be benign |
|---|---|
| Trusted static values written to GITHUB_ENV (a version string from a lockfile) | No untrusted context and no dangerous variable → no finding |
| A sanitized value written under a fixed name with a random heredoc delimiter | Safe cross-step passing; review the step, but the scanner only flags untrusted context on the write line |

## Limitations

- **Single-line reasoning.** The scanner matches untrusted context on the same logical line as the env-file write. A value laundered through an intermediate shell variable first (`x="${{ github.event.issue.title }}"; echo "K=$x" >> "$GITHUB_ENV"`) would be missed — though that form is itself worth flagging and is a candidate for a future vector.
- **Dangerous-var list is fixed.** Only the known execution-hijacking variables are treated as dangerous when static; an application-specific variable that controls code loading would not be recognized.
