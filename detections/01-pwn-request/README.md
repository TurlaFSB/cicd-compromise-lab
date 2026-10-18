# Detection — scenario 01 (pwn request)

## What it detects

The "pwn request" pattern: a GitHub Actions workflow triggered by `pull_request_target` that checks out the PR's head commit and executes code from it. This gives an external contributor's code access to the base repo's `GITHUB_TOKEN` and secrets.

## Detection methods

### 1. Sigma rule (`pwn-request.yml`)

A Sigma rule for static analysis of workflow YAML files. It fires when all three conditions are met:

1. The workflow triggers on `pull_request_target`
2. A checkout step references the PR's head (`github.event.pull_request.head.sha`, `.head.ref`, or `github.head_ref`)
3. The job runs shell commands after checkout (`run:` steps)

This rule can be consumed by any tool that parses GitHub Actions workflow files and evaluates Sigma-style conditions. It can also be integrated into a pre-commit hook or CI gate that scans `.github/workflows/` on every push.

### 2. Detection script (`detect.sh`)

A bash script with two modes:

**Static mode** — scans local workflow files:

```bash
./detect.sh static /path/to/repo
```

Checks every `.yml`/`.yaml` file in `.github/workflows/` for the three-part pattern. Reports findings with file name, line numbers, and the specific dangerous lines.

**Runtime mode** — queries the GitHub Actions API:

```bash
./detect.sh runtime owner/repo --days 7
```

Finds all `pull_request_target` runs in the given time window, fetches each run's workflow definition, and checks whether it contains the vulnerable pattern. Also flags runs triggered by PRs from forks, which represent the highest-risk case (external code running with internal privileges).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No pwn request pattern found |
| 1 | Pattern DETECTED — at least one finding |
| 2 | Usage error or missing dependency |

## Running the detection against the lab

```bash
# Static: scan the vulnerable target repo
./detect.sh static ~/pwn-request-target
# Expected: FINDING on ci.yml

# Static: scan the hardened version
# (Copy hardened/01-pwn-request/ci.yml into a mock .github/workflows/)
# Expected: OK, no findings

# Runtime: check for pull_request_target runs on the target
./detect.sh runtime turla-lab-targets/pwn-request-target --days 30
# Expected: FINDING for any runs from the attack
```

## Limitations

- The static scanner uses grep, not a full YAML parser. It catches the standard patterns but could miss obfuscated variants (e.g., constructing the ref string dynamically). For production use, pair with `zizmor` or `actionlint`.
- The runtime scanner requires `gh` CLI access to the target repo. It checks the workflow definition on the default branch, which may differ from what actually ran if the workflow was modified between the run and the scan.
- GitHub Free does not provide audit log streaming. The API-based approach is polling, not real-time.

## References

- [OWASP CICD-SEC-4 — Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [MITRE ATT&CK T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
