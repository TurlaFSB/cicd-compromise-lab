# Detection — scenario 03 (secret exfiltration)

## Overview

This detection suite identifies GitHub Actions workflows that expose secrets through six vectors: secrets printed in logs, masking bypass via transformation, overly broad secret scoping, overly broad permissions, missing environment protection, and mutable action tags.

## Detection methods

### Static analysis (`detect.sh static`)

Scans workflow YAML files for structural patterns that indicate secret exfiltration risk. No GitHub API access required.

```bash
./detect.sh static /path/to/repo
```

Six detection vectors:

| Vector | What it catches | How it works |
|---|---|---|
| Secret in logs | `echo "$DEPLOY_KEY"` in `run:` steps | Regex match for echo/printf/cat with secret variable references |
| Masking bypass | `echo "$SECRET" \| base64` | Regex match for secret references piped to encoding commands |
| Broad secret scope | `secrets.*` in workflow-level or build-job `env:` | Awk extraction of env blocks at different scope levels |
| Broad permissions | `contents: write` at workflow level | Awk extraction of workflow-level permissions block |
| No environment gate | Deploy job with secrets but no `environment:` | Checks deploy job section for environment declaration |
| Mutable action tags | `uses: action@v4` instead of SHA | Regex match for `@v` pattern in uses: declarations |

### Runtime analysis (`detect.sh runtime`)

Queries the GitHub Actions API for workflow definitions used in recent runs and checks them for the same patterns.

```bash
./detect.sh runtime owner/repo --days 30
```

Requires: `gh` CLI authenticated with access to the target repository.

## Sigma rule

`secret-exfil.yml` formalizes the detection in Sigma format, covering all six vectors with individual detection clauses combined via a logical `OR` condition.

### Detection logic

```
condition: secret_in_echo OR
           (secret_transformed AND secret_broad_scope) OR
           debug_exposure OR
           (broad_permissions AND secret_broad_scope)
```

The combined conditions reduce false positives: a workflow that uses `base64` for non-secret purposes won't trigger unless it also has overly broad secret scoping, and broad permissions alone only trigger when combined with secrets in scope.

## False positive handling

| Pattern | Why it might trigger | How to distinguish |
|---|---|---|
| `echo "$NON_SECRET" \| base64` | Base64 of non-secret data | Check whether the variable references a secret or a build artifact |
| `permissions: contents: write` | Release workflows legitimately need write | Check whether write is at workflow level (risky) or per-job (acceptable) |
| `ACTIONS_STEP_DEBUG` set intentionally | Temporary debugging | Should be removed after debugging; never enabled permanently |
| `env:` with cloud credentials | Legitimate deploy jobs | Check whether the env is in the deploy job only, or leaked to build |

## Limitations

1. **Cannot detect runtime exfiltration** — if a dependency sends `process.env.SECRET` to an external server via HTTP, static analysis cannot detect it. Runtime egress monitoring (e.g., StepSecurity Harden-Runner) is needed.
2. **Cannot detect indirect secret access** — a step that reads `/proc/self/environ` or the runner's `_runner` directory can access secrets without referencing them in YAML.
3. **Pattern-based matching** — unusual secret names or non-standard output methods may bypass the grep patterns. The scanner covers common patterns, not all possible variations.
4. **No OIDC validation** — the scanner checks whether static secrets are used, but cannot verify whether OIDC federation is properly configured as a replacement.

## Usage examples

```bash
# Scan a local repo
./detect.sh static /path/to/checkout

# Scan a remote repo via API (last 30 days)
./detect.sh runtime myorg/myrepo --days 30

# Scan all repos in an org
for repo in $(gh repo list myorg --limit 100 --json nameWithOwner -q '.[].nameWithOwner'); do
  echo "--- $repo ---"
  ./detect.sh runtime "$repo" --days 30
done
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No secret exfiltration pattern found |
| 1 | Pattern DETECTED — findings printed to stdout |
| 2 | Usage error or missing dependency |
