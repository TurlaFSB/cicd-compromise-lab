# Scenario 04 — Mutable action tag hijack

**OWASP:** CICD-SEC-3 (Dependency Chain Abuse) · **MITRE ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)

## Target

A CI workflow in `turla-lab-targets/tag-hijack-target` (or any repo) that references third-party GitHub Actions by mutable tags: `uses: org/action@v1`.

## The vulnerability

GitHub Actions are referenced in workflow YAML using the `uses:` directive with a Git ref after `@`:

```yaml
- uses: actions/checkout@v4          # ← mutable tag
- uses: actions/setup-node@v4        # ← mutable tag
- uses: turla-lab-targets/lab-helper-action@v1  # ← mutable tag
```

A Git tag is a mutable ref. Any account with push access to the action's repository can `git tag -f v1 <new-commit> && git push --force origin v1`, repointing the tag to an arbitrary commit. The next workflow run in every consuming repository silently executes the new code with all the permissions and secrets the step has access to.

### Why this is dangerous

| Factor | Impact |
|---|---|
| **Silent execution** | No notification, no diff, no approval flow. The workflow file hasn't changed — the tag it references now points elsewhere. |
| **Fan-out** | A single popular action can be consumed by thousands of repos. The March 2025 `tj-actions/changed-files` compromise (CVE-2025-30066) exposed roughly 23,000 repositories that referenced the action, according to public incident reports. |
| **Full environment access** | The compromised action code runs with the same `GITHUB_TOKEN`, secrets, and environment variables as the step it replaces. |
| **Invisible in CI logs** | Workflow logs don't show what commit a tag resolved to before vs. after the retagging. Without `@sha` pinning, there's no forensic trail. |

### Attack surface

Five categories of mutable references:

| Vector | Example | Risk |
|---|---|---|
| Version tag | `@v1`, `@v2.3`, `@v4.1.0` | Can be force-pushed by upstream maintainer or compromised account |
| Branch ref | `@main`, `@master`, `@develop` | Every upstream push changes what runs |
| Special tag | `@latest`, `@stable`, `@nightly` | Floating by convention; often automated |
| Short SHA | `@abc1234` | Not a full commit ref; can be ambiguous or collide |
| No ref | `uses: org/action` | Implicitly tracks default branch — always mutable |

### Compromise scenarios

1. **Malicious maintainer**: a trusted action author pushes a backdoored commit and retags.
2. **Account compromise**: an attacker gains access to the action author's GitHub account (credential stuffing, leaked PAT, phished session).
3. **Supply-chain chain**: a dependency of the action is compromised, and the action author unknowingly publishes a new release containing the compromised dependency.
4. **Abandoned action**: an action with a popular tag is archived. The author's account is later repurposed or sold.

## Attack simulation

The `payload/` directory contains a compromised version of `turla-lab-targets/lab-helper-action` that demonstrates what happens after a tag hijack. The compromised `action.yml`:

1. Runs the original functionality as camouflage (the deploy step still works).
2. Injects a "post-deploy telemetry" step that demonstrates secret access:
   - Prints the lengths of `DEPLOY_TOKEN`, `NPM_TOKEN`, and `GITHUB_TOKEN`.
   - Prints the repository, workflow name, run ID, and commit SHA.
   - In a real attack, these values (plus raw secrets) would be exfiltrated to an attacker-controlled endpoint.

The `vulnerable-ci.yml` is the target workflow with 11 mutable tag references across 4 jobs.

## Evidence

This scenario does not require a live attack to demonstrate — the vulnerability is structural. The detection scanner (`detections/04-tag-hijack/detect.sh`) proves that the vulnerable workflow is exploitable and the hardened workflow is not.

Scanner output against `vulnerable-ci.yml`:
- 11 `FINDING` lines, one per mutable tag reference
- Exit code 1 (vulnerable)

Scanner output against `hardened/04-tag-hijack/ci.yml`:
- 0 findings
- Exit code 0 (secure)

## Fix direction

See `hardened/04-tag-hijack/`. Summary:

1. **SHA pinning**: replace every `@vN` with the full 40-character commit SHA behind that tag. Note the human-readable tag in a trailing comment.
2. **Dependabot / Renovate**: configure automated PR creation when upstream publishes new versions. The PR shows the diff between the old and new SHA, forcing human review.
3. **CI gate**: run `zizmor` or `actionlint` as a CI check to reject PRs that introduce mutable tag references.
4. **persist-credentials: false**: on every `actions/checkout` step, prevent the cloned repo from retaining the `GITHUB_TOKEN` in its Git config.
