# Scenario 10 — GITHUB_TOKEN over-privilege

**OWASP:** CICD-SEC-5 (Insufficient Pipeline-Based Access Controls) · **MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)

## Target

Three workflows whose automatically issued `GITHUB_TOKEN` carries far more authority than the work requires:

| File | Flaw |
|---|---|
| `ci.yml` | `permissions: write-all`, on a `pull_request_target` trigger a fork PR can fire |
| `labeler.yml` | no `permissions:` block anywhere — the token takes the repository default |
| `triage.yml` | `contents`, `packages` and `id-token` write on an `issue_comment` trigger anyone can fire |

## The vulnerability

Every workflow run receives a short-lived `GITHUB_TOKEN`. What it may do is decided by, in order: the job's `permissions:`, the workflow's `permissions:`, then the repository or organisation default. Older repositories and many organisations still default to **read-write**, so a workflow that says nothing quietly holds write access to contents, packages, Actions and more.

The token is only dangerous if a step is compromised, but that is exactly the assumption every earlier scenario in this lab makes true: a poisoned dependency (04), an injected command (02, 08), a tampered cache (05), a hijacked reusable workflow (09). Over-privilege is the **amplifier** — it decides whether one bad step is an annoyance or a full takeover.

| Scope held | What a compromised step can do |
|---|---|
| `contents: write` | push commits and tags to unprotected branches, create or overwrite releases |
| `actions: write` | delete Actions caches and artifacts, enabling the cache poisoning of scenario 05 |
| `packages: write` | publish or overwrite packages consumed downstream |
| `id-token: write` | mint OIDC tokens and assume any cloud role whose trust policy allows the repo |
| `pull-requests: write` | label, comment on, and (if allowed) approve pull requests |

## Attack path

1. A fork PR (or a comment, for `triage.yml`) starts a workflow that outsiders can trigger.
2. Any step the attacker can influence runs with the over-broad token in its environment.
3. The attacker pushes a tag or release, overwrites a package, deletes the cache to force a re-poison, or requests a cloud identity token.

## Simulation

[`simulate.sh`](simulate.sh) resolves the **effective** token for every job the way GitHub does and prints what each write scope unlocks:

```bash
./simulate.sh                 # judge the three vulnerable workflows
./simulate.sh other.yml ...   # judge specific workflows
```

It condemns a job when a high-risk write scope is either reachable from an untrusted trigger or inherited rather than declared on the job. Exit `1` means over-privileged, `0` means scoped. The repository default is assumed permissive.

## Fix direction

See `hardened/10-token-overprivilege/`. Summary:

1. Set a workflow-level floor: `permissions: contents: read`, or `{}` for deny-by-default.
2. Grant write scopes **per job**, narrowly, next to the step that uses them.
3. Never combine untrusted triggers with high-risk write scopes.
4. Set the repository and organisation default to read-only so a forgotten block fails safe.
