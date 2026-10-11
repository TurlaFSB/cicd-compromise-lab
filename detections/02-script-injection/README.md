# Detection — scenario 02 (script injection via template expansion)

## What it detects

GitHub Actions workflows that interpolate untrusted context values directly into `run:` shell steps using `${{ }}` template expansion. GitHub Actions expands these expressions as literal string substitution **before** the shell parses the line, so attacker-controlled input containing shell metacharacters (backticks, `$()`, `;`, `&&`, `|`, newlines) executes as code.

The following untrusted contexts are checked:

| Context | Source of attacker control |
|---|---|
| `github.event.issue.title` / `.body` | Issue author |
| `github.event.pull_request.title` / `.body` / `.head.ref` / `.head.label` | PR author |
| `github.event.discussion.title` / `.body` | Discussion author |
| `github.event.comment.body` | Comment author |
| `github.event.review.body` / `review_comment.body` | Reviewer |
| `github.event.head_commit.message` / `.author.name` / `.author.email` | Commit author |
| `github.head_ref` | Branch creator |
| `github.event.pages[*].page_name` | Wiki editor |

## Detection methods

### 1. Sigma rule (`script-injection.yml`)

A Sigma rule for static analysis of workflow YAML files. It fires when both conditions are met:

1. The workflow has a `run:` step (shell execution)
2. An untrusted context expression appears in the `run:` step content

This rule can be consumed by any tool that parses GitHub Actions workflow files and evaluates Sigma-style conditions, or integrated into a pre-commit hook or CI gate.

### 2. Detection script (`detect.sh`)

A bash script with two modes:

**Static mode** — scans local workflow files:

```bash
./detect.sh static /path/to/repo
```

Uses awk to extract `run:` block content (multi-line and single-line), then checks extracted lines for `${{ untrusted_context }}` patterns. This avoids false positives from `${{ }}` used safely in `env:` mappings, `if:` conditions, or `with:` inputs.

**Runtime mode** — queries the GitHub Actions API:

```bash
./detect.sh runtime owner/repo --days 7
```

Fetches all active workflow definitions from the repository and checks each one for the script injection pattern. Also reports the number of recent runs for any vulnerable workflow.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No script injection pattern found |
| 1 | Pattern DETECTED — at least one finding |
| 2 | Usage error or missing dependency |

## Running the detection against the lab

```bash
# Static: scan the vulnerable target repo
./detect.sh static /home/claude/script-injection-target
# Expected: FINDING on triage.yml — github.event.issue.title in run: step

# Static: scan the hardened version
# (Copy hardened/02-script-injection/triage.yml into a mock .github/workflows/)
# Expected: OK, no findings (title is in env:, not in run:)

# Runtime: check workflows on the target repo
./detect.sh runtime turla-lab-targets/script-injection-target --days 30
# Expected: FINDING for the triage workflow
```

## False positive handling

The detection script specifically extracts `run:` block content using awk, so it does not flag workflows that pass untrusted context through `env:` mappings (the correct fix). For example, this is safe and will NOT trigger a finding:

```yaml
env:
  ISSUE_TITLE: ${{ github.event.issue.title }}   # Safe: set by runner
run: |
  echo "Title: ${ISSUE_TITLE}"                    # Safe: shell variable
```

But this WILL trigger a finding:

```yaml
run: |
  echo "Title: ${{ github.event.issue.title }}"   # Dangerous: template in shell
```

## Limitations

- The static scanner uses awk and grep, not a full YAML parser. It handles standard indentation patterns but could miss unconventional formatting. For production use, pair with [`zizmor`](https://github.com/woodruffw/zizmor) or [`actionlint`](https://github.com/rhysd/actionlint).
- The context list covers the most common attacker-controlled inputs but is not exhaustive. Custom event payloads (`github.event.client_payload.*`) from `repository_dispatch` are also attacker-controlled but not checked.
- The runtime scanner requires `gh` CLI access to the target repo.

## References

- [GitHub Docs — Understanding the risk of script injections](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [GitHub Security Lab — Keeping your Actions safe](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [OWASP CICD-SEC-4 — Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
