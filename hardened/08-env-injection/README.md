# Hardened workflow — Scenario 08: GITHUB_ENV / GITHUB_PATH injection

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Untrusted title | `echo "ISSUE_TITLE=${{ … }}" >> $GITHUB_ENV` | step-scoped `env: ISSUE_TITLE: ${{ … }}` |
| Untrusted body | `echo "${{ … }}" >> $GITHUB_PATH` | not written anywhere |
| Cross-step passing | raw untrusted value | sanitized value, fixed name, random heredoc delimiter |
| Injection surface | KEY=VALUE and PATH injection | none — untrusted data never defines a variable |

## Why each change works

### 1. Untrusted data via `env:`, not the env files

```yaml
- name: Process
  env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: |
    echo "Triaging: $ISSUE_TITLE"
```

The runner sets `ISSUE_TITLE` directly in the step's environment. The value is never parsed as `GITHUB_ENV` lines, so a newline in the title is just part of the string — it cannot inject a second variable. This is the same indirection scenario 02 uses against shell injection.

### 2. `$GITHUB_PATH` is never written

The body is not used to build a `PATH` entry, so an attacker cannot prepend a directory and shim `node`/`npm`.

### 3. Safe cross-step passing (when truly needed)

If a value must survive to a later step, the hardened workflow shows the safe pattern:

```bash
safe=$(printf '%s' "$ISSUE_TITLE" | tr -cd '[:alnum:]-_ ' | cut -c1-80)
delim="EOF_$(openssl rand -hex 8)"
{ echo "SAFE_LABEL<<$delim"; printf '%s\n' "$safe"; echo "$delim"; } >> "$GITHUB_ENV"
```

- The variable name is **fixed** (`SAFE_LABEL`), so untrusted text cannot introduce a new name.
- The value is **sanitized** to a safe character set.
- A **random heredoc delimiter** means the value cannot close the block early to inject following lines.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-4 | Keep untrusted input out of execution | Untrusted data is data, never an environment definition |
| MITRE T1574 | Deny execution-flow hijacks | No attacker control over `NODE_OPTIONS`/`PATH`/loader variables |

## Deployment

1. Replace the target repo's workflow with `triage.yml` from this directory.
2. Audit for any other `>> $GITHUB_ENV` / `>> $GITHUB_PATH` writes that carry untrusted context.
3. Verify: `./verify/08-env-injection/verify.sh static` (9/9 checks).

## Verification

9 structural checks confirm the fix — scanner clears the hardened workflow and flags the vulnerable one, the simulation reports SAFE vs. INJECTABLE, and the workflow writes no untrusted context to the env files, never writes `GITHUB_PATH`, passes the title via step-scoped `env:`, uses a heredoc delimiter for any `GITHUB_ENV` write, and pins actions by SHA.
