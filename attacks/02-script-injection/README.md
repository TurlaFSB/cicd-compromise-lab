# Attack — scenario 02 (script injection via issue title)

## Overview

This scenario demonstrates **script injection** in GitHub Actions workflows caused by `${{ }}` template expansion of untrusted input inside `run:` shell steps.

The target workflow (`turla-lab-targets/script-injection-target`) triggers on `issues: opened` and interpolates `github.event.issue.title` directly into a shell command:

```yaml
run: |
  echo "Thanks for opening: ${{ github.event.issue.title }}"
```

An attacker opens an issue whose title contains shell metacharacters. GitHub Actions splices the title verbatim into the generated shell script before the runner executes it, turning attacker-controlled text into executable code.

## Attack surface

### Why this works

GitHub Actions `${{ }}` expressions are **not** shell-aware. The expansion happens at the workflow engine level, before the shell is even launched. The engine performs a simple string replacement:

```
Template:  echo "Thanks for opening: ${{ github.event.issue.title }}"
Title:     test `whoami`
Result:    echo "Thanks for opening: test `whoami`"
```

The shell receives the final string and executes the backtick-enclosed command as part of normal command substitution. There is no escaping, no sandboxing, and no indication that part of the string came from untrusted input.

### What the attacker gets

The injected commands run with the full environment of the workflow job:

- **`GITHUB_TOKEN`** — the token GitHub generates for the workflow run, with whatever permissions the workflow declares (in this case, `contents: read` and `issues: write`).
- **Repo secrets** — any secret passed in the `env:` block of the same step. In the vulnerable workflow, `DUMMY_CLOUD_KEY1` is exposed.
- **Runner access** — full shell access on the ephemeral GitHub-hosted runner, including network access to exfiltrate data.

### Injection vectors

Any shell metacharacter in the issue title triggers code execution:

| Character | Shell behavior |
|---|---|
| `` `cmd` `` | Command substitution (backticks) |
| `$(cmd)` | Command substitution (POSIX) |
| `; cmd` | Command separator |
| `&& cmd` | Conditional execution |
| `\| cmd` | Pipe |
| Newlines | Command separator |

### Affected contexts

The same vulnerability applies to any untrusted context interpolated in a `run:` step, not just issue titles. See `detections/02-script-injection/README.md` for the full list of untrusted GitHub Actions contexts.

## Evidence

A successful attack produces observable evidence:

1. **Workflow run logs** show the injected commands executing in the triage step.
2. **Repo artifacts or issues** created by the payload (e.g., a new issue containing a hashed secret value, proving the attacker could read it).
3. **API audit trail** — any actions taken with the stolen `GITHUB_TOKEN` appear in the repo's audit log.

The `payload/` directory contains the evidence-collection approach:

- The payload hashes the `DUMMY_CLOUD_KEY1` secret (to prove access without exposing the value) and posts the hash as a new issue, creating a durable evidence trail.

## MITRE ATT&CK mapping

| Technique | Application |
|---|---|
| T1059.004 — Unix Shell | Shell injection via issue title in GitHub Actions `run:` step |
| T1552.001 — Credentials in Files | Secrets exposed as environment variables to the injected shell |
| T1567 — Exfiltration Over Web Service | Exfiltration via `gh` CLI or direct API calls from the runner |

## OWASP CI/CD mapping

| Risk | Application |
|---|---|
| CICD-SEC-1 — Insufficient Flow Control | Any user who can open an issue triggers code execution |
| CICD-SEC-4 — Poisoned Pipeline Execution | Attacker-controlled input executes as code in the pipeline |

## Fix

See `hardened/02-script-injection/triage.yml` — the fix passes untrusted context through `env:` variables instead of `${{ }}` interpolation. The detection scanner in `detections/02-script-injection/` identifies vulnerable workflows.

## References

- [GitHub Docs — Security hardening: script injections](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [GitHub Security Lab — Keeping your Actions safe](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [OWASP CICD-SEC-4 — Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- Peled & Omer (2021) — "Vulnerability Analysis of CI/CD Pipelines" — academic study documenting hundreds of public GitHub repos vulnerable to this pattern
