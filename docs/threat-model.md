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

**Status:** Complete — detection operational (5 vectors), hardened workflow verified (13/13 checks pass).

**Technique:** a workflow references a third-party action by a mutable tag (`uses: org/action@v1`); if that tag is retagged upstream (compromise or malicious maintainer), the workflow silently runs new code next run. Five mutable reference types detected: version tags, branch refs, special tags, short SHAs, and missing refs.
**OWASP:** CICD-SEC-3 (Dependency Chain Abuse) · **ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)
**Fix:** pin every third-party action to a full commit SHA, not a tag; use Dependabot/Renovate to track and review SHA bumps; `persist-credentials: false` on checkout; per-job least-privilege permissions; environment protection on deploy jobs. See `hardened/04-tag-hijack/`.

### 05 — Cache poisoning ✅

**Status:** Complete — detection operational (5 vectors + cache-scoping simulation), hardened workflows verified (12/12 checks pass).

**Technique:** a build cache (`actions/cache`) is writable by an untrusted trigger (fork `pull_request`) under a static, forgeable key, and restored by a privileged workflow (push/release) that then builds from the poisoned content. GitHub's cache scoping lets a fork PR's entry be restored by the default-branch build.
**OWASP:** CICD-SEC-9 (Improper Artifact Integrity Validation) · **ATT&CK:** T1195.002 (Compromise Software Supply Chain)
**Impact:** an external contributor injects tampered dependencies or build output into a published release artifact without merging any code.
**Fix:** read-only `actions/cache/restore` on untrusted triggers, keys bound to `hashFiles()`, no `restore-keys`, cache downloads not output, and always rebuild from source in the release job. See `hardened/05-cache-poisoning/`.

### 06 — Artifact tampering ✅

**Status:** Complete — detection operational (3 vectors + tamper simulation), hardened workflow verified (11/11 checks pass).

**Technique:** an artifact produced by the build job is modified before the release job consumes and publishes it, since `actions/upload-artifact`/`download-artifact` carry no integrity guarantee by default. Nothing binds the build output to the published bytes.
**OWASP:** CICD-SEC-9 (Improper Artifact Integrity Validation) · **ATT&CK:** T1195 (Supply Chain Compromise)
**Impact:** a tampered artifact (malicious postinstall, backdoored bundle) is published under the project's real name and version to every downstream consumer.
**Fix:** `actions/attest-build-provenance` signs a SLSA build-provenance attestation over the artifact in the build job; the publish job runs `gh attestation verify` (plus a SHA-256 checksum re-check) before publishing. See `hardened/06-artifact-tampering/`.

### 07 — Self-hosted runner persistence ✅

**Status:** Complete — detection operational (3 vectors + persistence simulation), hardened workflow verified (9/9 checks pass).

**Technique:** a workflow runs untrusted `pull_request` code on a self-hosted runner; because such runners are reused between jobs, a fork PR drops a persistence mechanism (cron, shell profile, user systemd, background listener) that survives into later, privileged jobs on the same machine.
**OWASP:** CICD-SEC-7 (Insecure System Configuration) · **ATT&CK:** T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution)
**Impact:** an implant waits for a privileged job and steals its secrets or tampers its build — no merge required.
**Fix:** run untrusted code on ephemeral GitHub-hosted runners (or single-use `--ephemeral` self-hosted runners in an isolated pool); never share a runner between untrusted and trusted workloads. See `hardened/07-runner-persistence/`.

### 08 — GITHUB_ENV / GITHUB_PATH injection ✅

**Status:** Complete — detection operational (3 vectors + injection simulation), hardened workflow verified (9/9 checks pass).

**Technique:** a workflow writes untrusted issue/PR text into `$GITHUB_ENV` or `$GITHUB_PATH`; a crafted value injects an extra environment variable (NODE_OPTIONS, LD_PRELOAD) or a PATH entry that hijacks a later step.
**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **ATT&CK:** T1574 (Hijack Execution Flow)
**Impact:** arbitrary code execution in a later step via loader/PATH hijacking, from attacker-controlled input alone.
**Fix:** pass untrusted data through step-scoped `env:`, never write it to the env files; never write `$GITHUB_PATH` with untrusted data; for cross-step values use a fixed name, sanitized value, and random heredoc delimiter. See `hardened/08-env-injection/`.

### 09 — Reusable workflow trust boundary ✅

**Status:** Complete — detection operational (3 vectors), hardened caller verified (7/7 checks pass).

**Technique:** a caller invokes an external reusable workflow by a mutable ref (`@main`) and passes `secrets: inherit`, so the upstream owner controls code that runs with every one of the caller's secrets and can change it at any time.
**OWASP:** CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-4 (Poisoned Pipeline Execution) · **ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)
**Impact:** full secret exposure to, and silent code change from, an external party.
**Fix:** pin the reusable workflow by commit SHA; pass only the needed secrets by name, never `secrets: inherit`. See `hardened/09-reusable-workflow/`.

### 10 — GITHUB_TOKEN over-privilege ✅

**Status:** Complete — detection operational (4 vectors + effective-token simulation), hardened workflows verified (15/15 checks pass).

**Technique:** a workflow's `GITHUB_TOKEN` holds more authority than its jobs need — `permissions: write-all`, no `permissions:` block (repository default, often read-write), write scopes declared at workflow level, or high-risk write scopes reachable from triggers an outsider can fire.
**OWASP:** CICD-SEC-5 (Insufficient PBAC), CICD-SEC-2 (Inadequate IAM) · **ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)
**Impact:** amplifies every other compromise — a single hijacked step can push code, publish packages, delete caches, or mint OIDC tokens.
**Fix:** read-only workflow-level floor, write scopes per job, no high-risk write on untrusted triggers, read-only repository default. See `hardened/10-token-overprivilege/`.

### 11 — workflow_run artifact poisoning ✅

**Status:** Complete — detection operational (3 vectors + poisoning simulation), hardened workflows verified (11/11 checks pass).

**Technique:** a `workflow_run` handler runs in the base repo's context (secrets, read/write token) even when the run that triggered it came from a fork PR. A handler that consumes the upstream run's output unsafely — checking out its head, executing its downloaded artifact, or splicing its branch name/title into a shell — gives a fork-PR author code execution with the base repo's privileges.
**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **ATT&CK:** T1195 (Supply Chain Compromise)
**Impact:** full secret exposure and arbitrary privileged code execution from an unmerged fork pull request.
**Fix:** upload only minimal, validated data (a PR number) from the producer; in the handler, never check out the head or execute the artifact, pass `workflow_run` context via `env:`, and keep a read-only floor with `pull-requests: write` only on the job. See `hardened/11-workflow-run-poisoning/`.

### 12 — OIDC trust policy misconfiguration ✅

**Status:** Complete — detection operational (5 vectors across cloud policy + workflow, plus subject-matching simulation), hardened configuration verified (14/14 checks pass).

**Technique:** a cloud OIDC trust policy accepts an over-broad GitHub subject (`repo:org/*`, any ref) or pins no audience, while the workflow grants `id-token: write` broadly (workflow level, untrusted trigger). Any run the org can start — a fork PR included — mints a token the policy admits and exchanges it for real cloud credentials.
**OWASP:** CICD-SEC-5 (Insufficient PBAC), CICD-SEC-2 (Inadequate IAM) · **ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)
**Impact:** an unintended or fork-controlled run assumes a cloud role and acts in the account with no stored secret to steal.
**Fix:** `StringEquals` on both `sub` (one repo + ref, or a protected environment) and `aud`; `id-token: write` per job under a read-only floor; deploy only from trusted triggers. See `hardened/12-oidc-trust-policy/`.

### 13 — credential leakage via artifacts ✅

**Status:** Complete — detection operational (4 vectors + leak simulation), hardened workflow verified (14/14 checks pass).

**Technique:** a build job leaks secrets into an uploaded artifact — a persisted checkout token in `.git/config`, a secret written to a file, a broad upload path, or `include-hidden-files: true`. Anyone who can download the artifact (anyone, for a public repo) extracts the credential.
**OWASP:** CICD-SEC-6 (Insufficient Credential Hygiene) · **ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files)
**Impact:** long-lived tokens (npm, cloud, deploy keys) and the checkout token exposed to anyone with artifact access.
**Fix:** `persist-credentials: false`, secrets via `env:` not disk, upload only build output, no forced hidden files. See `hardened/13-artifact-cred-leak/`.

### 14 — dependency confusion and install-script abuse ✅

**Status:** Complete — detection operational (4 vectors across workflow + npm config, plus resolution/install-script simulation), hardened configuration verified (15/15 checks pass).

**Technique:** the install phase pulls or runs attacker code — `npm install` with an unpinned internal scope lets a higher-versioned public package of the same name win (dependency confusion); installs run lifecycle scripts by default; and `curl | sh` runs an unverified remote script.
**OWASP:** CICD-SEC-3 (Dependency Chain Abuse) · **ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)
**Impact:** arbitrary code execution at install time, before any test or review, from a package or script the project never intended to run.
**Fix:** `npm ci --ignore-scripts`, pin internal scopes to a private registry (`@scope:registry=`) with `ignore-scripts=true`, and fetch-verify-then-run instead of piping the network into a shell. See `hardened/14-dependency-confusion/`.

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
