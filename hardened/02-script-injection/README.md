# Hardened workflow — scenario 02 (script injection via issue title)

## Vulnerability recap

The original workflow (`.github/workflows/triage.yml` in `turla-lab-targets/script-injection-target`) interpolates `github.event.issue.title` directly into a `run:` shell step using `${{ }}` template expansion:

```yaml
run: |
  echo "Thanks for opening: ${{ github.event.issue.title }}"
```

GitHub Actions expands `${{ }}` expressions as a literal string substitution **before** the shell ever parses the line. The issue title is attacker-controlled text. If it contains shell metacharacters — backticks, `$()`, `;`, `&&`, pipes, or newlines — those characters land in the generated script verbatim and execute with the full privileges of the workflow, including access to `GITHUB_TOKEN` and any secrets in scope.

## What changed

| Vulnerable pattern | Hardened pattern | Why |
|---|---|---|
| `${{ github.event.issue.title }}` directly in `run:` | Title passed through `env: ISSUE_TITLE:` | Environment variables are set by the runner, not by shell expansion — metacharacters in the value are data, never code |
| Untrusted value spliced into shell script text | Variable referenced as `"${ISSUE_TITLE}"` with double quotes | Shell treats the value as a single string regardless of content |
| `DUMMY_CLOUD_KEY` in `env:` of the same step | Secret removed from the workflow entirely | Secrets should only be passed to steps that need them — the triage greeting never did |
| Actions pinned by mutable tag (`@v4`) | No third-party actions used; if added, pin by full commit SHA | Prevents CICD-SEC-3 (mutable tag hijack) |

## The fix in detail

The hardened workflow uses a two-layer defense:

### Layer 1: Environment variable indirection

```yaml
env:
  ISSUE_TITLE: ${{ github.event.issue.title }}
run: |
  echo "Thanks for opening: ${ISSUE_TITLE}"
```

The `env:` mapping is processed by the GitHub Actions runner. It stores the issue title as a byte string in the process environment **before** the shell starts. The shell never sees `${{ }}` — it sees an ordinary variable reference. Even if the title contains `` `rm -rf /` ``, the shell prints that string literally.

### Layer 2: Shell quoting

The variable is referenced inside double quotes (`"${ISSUE_TITLE}"`), which prevents word splitting and glob expansion. Without quotes, a title containing `* ; rm -rf /` could still cause problems through shell word splitting. With quotes, it is always a single string token.

### Layer 3: Secret removal

The vulnerable workflow passed `DUMMY_CLOUD_KEY` in the `env:` block of the same step that ran the injected shell code. Even with the injection fixed, exposing secrets to steps that don't need them violates least privilege. The hardened workflow removes it entirely.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  issues: [opened]                                            │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Job: triage                                             │ │
│  │ Permissions: contents read, issues write                │ │
│  │                                                         │ │
│  │  env:                                                   │ │
│  │    ISSUE_TITLE ← ${{ github.event.issue.title }}        │ │
│  │    (set by runner as data, not shell-expanded)           │ │
│  │                                                         │ │
│  │  run:                                                   │ │
│  │    echo "${ISSUE_TITLE}"                                │ │
│  │    (shell sees a variable, not attacker-controlled code) │ │
│  │                                                         │ │
│  │  ✗ No secrets in scope                                  │ │
│  │  ✗ No checkout (nothing to tamper with)                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Standards mapping

| Control | Standard | Status |
|---|---|---|
| Untrusted data never interpolated into shell scripts | OWASP CICD-SEC-4 (Poisoned Pipeline Execution) | Eliminated |
| No unnecessary secrets in workflow steps | OWASP CICD-SEC-5 (Insufficient PBAC) | Applied |
| Shell injection via attacker-controlled input prevented | MITRE ATT&CK T1059.004 (Unix Shell) | Prevented |
| Attacker cannot abuse issue events to execute code | OWASP CICD-SEC-1 (Insufficient Flow Control) | Mitigated |

## Deployment

To apply this fix to the target repo:

1. Replace `.github/workflows/triage.yml` in `turla-lab-targets/script-injection-target` with `triage.yml` from this directory.
2. Remove the `DUMMY_CLOUD_KEY1` secret from the repo settings — the triage workflow should not need any secret.
3. Test by opening an issue with shell metacharacters in the title — the title should be printed verbatim, not executed.

## Alternative fix: `github-script` action

Instead of a shell step, the triage logic could use `actions/github-script` (JavaScript), which avoids shell parsing entirely:

```yaml
- uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
  with:
    script: |
      const title = context.payload.issue.title;
      console.log(`Thanks for opening: ${title}`);
```

In JavaScript, `context.payload.issue.title` is a string variable — there is no shell to inject into. This is an equally valid approach. The env-variable fix was chosen here because it demonstrates the principle (separate data from code at the shell boundary) more directly and applies to any workflow that must use `run:` steps.

## References

- [GitHub Security Lab — Keeping your Actions safe: script injection](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [OWASP CICD-SEC-4 — Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [GitHub Docs — Security hardening: Understanding the risk of script injections](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
