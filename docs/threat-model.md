# Threat model — cicd-compromise-lab

## Purpose

This lab demonstrates, in a fully isolated and disposable environment, how a GitHub Actions pipeline can be compromised and how each compromise is detected and closed off. Every scenario in this document ends with a hardened workflow and an automated check that proves the original attack no longer works.

## System under test

A small, representative CI/CD setup under the `turla-lab-targets` org:

- A source repo with a build-and-release GitHub Actions pipeline (lint -> test -> build -> publish artifact).
- A `GITHUB_TOKEN` and a small set of dummy "cloud" credentials used only within the lab.
- One or more third-party actions pulled in as dependencies (pinned by tag, as most real-world repos do, which is itself the starting weakness).
- A release/publish job that consumes the build job's artifact.

Nothing in this system touches a real cloud account, a real secret, or infrastructure outside the lab org.

## Assets (what an attacker would want)

| Asset | Why it matters |
|---|---|
| `GITHUB_TOKEN` / repo-scoped credentials | Can push code, create releases, modify branch protection if over-privileged |
| Lab "cloud" credentials (dummy) | Stand in for deploy keys / cloud IAM creds a real pipeline would hold |
| Build artifact / release binary | If tampered with, becomes a supply-chain delivery vector to downstream consumers |
| Pipeline execution itself | Lets an attacker run arbitrary code on a GitHub-hosted (or self-hosted) runner |

## Trust boundaries

1. **Untrusted contributor -> repo**: anyone can open a PR or issue against a public repo. Titles, branch names, and file contents are attacker-controlled input.
2. **Workflow -> third-party action**: an action pulled in by a mutable tag (`@v1`) is trusted code that can change without the consuming repo's consent.
3. **Build job -> release job**: an artifact handed between jobs/workflows is trusted without integrity verification unless explicitly checked.
4. **Runner -> secrets**: any step in a job that has secrets in its environment can, in principle, exfiltrate them unless permissions and egress are constrained.

## Actors

- **External contributor (attacker)**: can open PRs/issues on the public target repo, cannot directly push to protected branches, cannot read repo secrets.
- **Maintainer (defender)**: owns the repo, writes workflows, reviews PRs, controls branch protection and environment rules.
- **Third-party action author**: controls code the maintainer trusts implicitly when pinning by tag instead of SHA.

## Scenario catalog

Each scenario below becomes its own folder under `attacks/`, `hardened/`, and `detections/`, with a write-up appended to this file as it's built.

### 01 — Pwn request ✅

**Status:** Complete — attack executed, detection operational, hardened workflow verified (10/10 checks pass).

**Technique:** a workflow triggered on `pull_request_target` (which runs with write permissions and repo secrets) checks out and executes the PR's own code.
**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **ATT&CK:** T1195 (Supply Chain Compromise)
**Impact:** attacker-controlled code runs with maintainer-level token and secret access.
**Fix:** split-job architecture — unprivileged `pull_request` job runs PR code with no secrets; privileged `pull_request_target` job posts status but never checks out code. All actions SHA-pinned. See `hardened/01-pwn-request/`.

### 02 — Script injection via PR/issue title ✅

**Status:** Complete — detection operational, hardened workflow verified (11/11 checks pass).

**Technique:** untrusted text (PR title, issue title, branch name) is interpolated directly into a `run:` shell step instead of passed as an environment variable.
**OWASP:** CICD-SEC-4, CICD-SEC-1 (Insufficient Flow Control) · **ATT&CK:** T1059.004 (Unix Shell)
**Impact:** arbitrary command execution on the runner with access to `GITHUB_TOKEN` and any secrets in the step's `env:` block.
**Fix:** pass untrusted context through `env:` variables (runner-set, not shell-expanded); double-quote variable references; remove unnecessary secrets from step scope. See `hardened/02-script-injection/`.

### 03 — Secret exfiltration ✅

**Status:** Complete — detection operational (6 vectors), hardened workflow verified (14/14 checks pass).

**Technique:** a workflow step prints an environment variable to logs, transforms secrets to bypass log masking (base64), scopes secrets to jobs that don't need them, uses overly broad workflow-level permissions, accesses secrets without environment protection, and stores static long-lived credentials.
**OWASP:** CICD-SEC-6 (Insufficient Credential Hygiene), CICD-SEC-5 (Insufficient PBAC) · **ATT&CK:** T1552 (Unsecured Credentials)
**Impact:** secrets exfiltrated from build logs, compromised dependencies, or debug output remain valid indefinitely.
**Fix:** per-job least-privilege permissions, step-scoped secrets, environment-gated deployments with required reviewers, no secrets in log output, SHA-pinned actions, OIDC federation guidance. See `hardened/03-secret-exfil/`.

### 04 — Mutable action tag hijack ✅

**Status:** Complete — detection operational (5 vectors), hardened workflow verified (12/12 checks pass).

**Technique:** a workflow references a third-party action by a mutable tag (`uses: org/action@v1`); if that tag is retagged upstream (compromise or malicious maintainer), the workflow silently runs new code next run. Five mutable reference types detected: version tags, branch refs, special tags, short SHAs, and missing refs.
**OWASP:** CICD-SEC-3 (Dependency Chain Abuse) · **ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)
**Fix:** pin every third-party action to a full commit SHA, not a tag; use Dependabot/Renovate to track and review SHA bumps; `persist-credentials: false` on checkout; per-job least-privilege permissions; environment protection on deploy jobs. See `hardened/04-tag-hijack/`.

### 05 — Cache poisoning
**Technique:** a build cache (e.g. `actions/cache`) keyed loosely enough that an attacker-controlled branch can poison a cache entry later restored by a trusted workflow run.
**OWASP:** CICD-SEC-9 (Improper Artifact Integrity Validation) · **ATT&CK:** T1195.002
**Fix direction:** scope cache keys tightly (include lockfile hash and branch), never restore caches written by untrusted-trigger workflows into privileged ones.

### 06 — Artifact tampering
**Technique:** an artifact produced by the build job is modified before the release job consumes and publishes it, since `actions/upload-artifact`/`download-artifact` carry no integrity guarantee by default.
**OWASP:** CICD-SEC-9 · **ATT&CK:** T1195
**Fix direction:** Sigstore/cosign keyless signing of the artifact in the build job, SLSA provenance attestation, and a verify step before the release job publishes.

### 07 — Self-hosted runner persistence (stretch)
**Technique:** a compromised job on a self-hosted runner drops a persistence mechanism that survives into later, unrelated jobs on the same runner.
**OWASP:** CICD-SEC-7 (Insecure System Configuration) · **ATT&CK:** T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution)
**Fix direction:** ephemeral, single-job runners only; never reuse a self-hosted runner across untrusted and trusted workloads.

## Detection strategy

Each scenario gets a corresponding detection in `detections/`, expressed as:
- A **Sigma rule** where the signal is log-shaped (workflow run logs, webhook/audit events available on GitHub Free).
- A plain-language **query description** for the same signal against GitHub's REST/GraphQL API, since full Enterprise audit-log streaming isn't available on the free plan this lab uses.

## Verification strategy

`verify/` holds a CI workflow that, after a scenario's hardened fix lands, re-runs that scenario's attack script against the hardened workflow and asserts it fails (exits non-zero / produces no exfiltrated evidence / is blocked by a check). This is the proof that the fix works, not just a description of it.

## Out of scope for v1

- Jenkins (possible phase 2, separate repo or separate top-level folder).
- Real cloud infrastructure of any kind.
- Any target outside the `turla-lab-targets` org.
