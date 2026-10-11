# CI/CD Pipeline Compromise Lab

A reproducible security lab that demonstrates real-world attacks against GitHub Actions CI/CD pipelines, detects them with Sigma rules and automated scanners, hardens the pipelines with structural fixes, and proves the hardening works through automated verification.

Every scenario follows the same closed loop:

```
Vulnerable workflow → Reproducible attack → Evidence → Detection rule → Hardened workflow → Automated verification
```

## Motivation

CI/CD pipelines hold secrets, publish artifacts, and deploy to production — making them one of the most valuable targets in a supply-chain attack. Public incidents (the 2025 `tj-actions/changed-files` compromise, the Codecov bash uploader attack, SolarWinds-style build tampering) demonstrate the pattern. Most training material stops at "here is a vulnerable pipeline." This lab covers the **full defensive cycle**: attack, detect, fix, and prove the fix works.

## Scenarios

| # | Scenario | OWASP CI/CD Risk | MITRE ATT&CK | Status |
|---|----------|------------------|--------------|--------|
| 01 | [Pwn request](#scenario-01--pwn-request) | CICD-SEC-4 | T1195 | Complete |
| 02 | [Script injection via issue title](#scenario-02--script-injection) | CICD-SEC-4, CICD-SEC-1 | T1059.004 | Complete |
| 03 | [Secret exfiltration](#scenario-03--secret-exfiltration) | CICD-SEC-6, CICD-SEC-5 | T1552 | Complete |
| 04 | [Mutable action tag hijack](#scenario-04--mutable-action-tag-hijack) | CICD-SEC-3 | T1195.001 | Planned |
| 05 | [Cache poisoning](#scenario-05--cache-poisoning) | CICD-SEC-9 | T1195.002 | Planned |
| 06 | [Artifact tampering](#scenario-06--artifact-tampering) | CICD-SEC-9 | T1195 | Planned |

### Scenario 01 — Pwn request

A workflow triggered on `pull_request_target` checks out and executes the PR author's code with the base repo's `GITHUB_TOKEN` and secrets. Any external contributor can run arbitrary code with maintainer-level access by opening a PR — no approval or merge required.

**Fix:** Split-job architecture separating untrusted code execution (`pull_request` trigger, no secrets) from privileged operations (`pull_request_target` trigger, no checkout). All actions pinned by commit SHA.

**Verification:** 10/10 structural checks pass. Detection scanner correctly flags the vulnerable workflow and clears the hardened one.

### Scenario 02 — Script injection

A workflow interpolates `github.event.issue.title` directly into a `run:` shell step via `${{ }}` template expansion. GitHub Actions performs this expansion as literal string substitution before the shell parses the line, so shell metacharacters in the issue title execute as code.

**Fix:** Pass untrusted context through `env:` variables (set by the runner, not by shell expansion). Double-quote variable references. Remove unnecessary secrets from step scope.

**Verification:** 11/11 structural checks pass. Detection scanner covers 20+ untrusted GitHub Actions contexts.

### Scenario 03 — Secret exfiltration

A workflow leaks secrets through six vectors: printing secrets in logs, base64-transforming secrets to bypass GitHub's log masking, scoping secrets to jobs that don't need them, granting overly broad permissions at the workflow level, accessing secrets without environment protection gates, and using static long-lived credentials that never expire.

**Fix:** Per-job least-privilege permissions, step-scoped secrets, environment-gated deployments with required reviewers, no secrets in log output, SHA-pinned actions, and guidance for replacing static keys with OIDC short-lived credentials.

**Verification:** 14/14 structural checks pass. Detection scanner catches all six vectors in the vulnerable workflow and clears the hardened one.

### Scenario 04 — Mutable action tag hijack

A workflow references a third-party action by mutable tag (`uses: org/action@v1`). If that tag is force-pushed upstream, the workflow silently runs new code on the next trigger.

**Fix:** Pin every third-party action to a full commit SHA. Use Dependabot or Renovate to track SHA bumps. Run `zizmor`/`actionlint` as a CI gate.

### Scenario 05 — Cache poisoning

A build cache keyed loosely enough that an attacker-controlled branch can poison entries later restored by trusted workflow runs.

**Fix:** Scope cache keys tightly (include lockfile hash and branch). Never restore caches written by untrusted-trigger workflows into privileged runs.

### Scenario 06 — Artifact tampering

An artifact produced by the build job is modified before the release job consumes it. `actions/upload-artifact`/`download-artifact` carry no integrity guarantee by default.

**Fix:** Sigstore/cosign keyless signing in the build job, SLSA provenance attestation, and a verification step before the release job publishes.

## Architecture

```
cicd-compromise-lab/                    turla-lab-targets/ (separate org)
├── attacks/                            ├── pwn-request-target/
│   ├── 01-pwn-request/                 │   └── .github/workflows/ci.yml
│   │   ├── attack.sh                   │
│   │   ├── payload/                    ├── script-injection-target/
│   │   └── evidence/                   │   └── .github/workflows/triage.yml
│   └── 02-script-injection/            │
│       ├── README.md                   └── secret-exfil-target/
│       └── payload/                        └── .github/workflows/deploy.yml
├── detections/
│   ├── 01-pwn-request/
│   │   ├── pwn-request.yml      ← Sigma rule
│   │   ├── detect.sh            ← static + runtime scanner
│   │   └── README.md
│   └── 02-script-injection/
│       ├── script-injection.yml ← Sigma rule
│       ├── detect.sh            ← static + runtime scanner
│       └── README.md
├── hardened/
│   ├── 01-pwn-request/
│   │   ├── ci.yml               ← hardened workflow
│   │   └── README.md
│   └── 02-script-injection/
│       ├── triage.yml           ← hardened workflow
│       └── README.md
├── verify/
│   ├── 01-pwn-request/
│   │   ├── verify.sh            ← 10 structural checks
│   │   └── README.md
│   └── 02-script-injection/
│       ├── verify.sh            ← 11 structural checks
│       └── README.md
├── docs/
│   └── threat-model.md
└── vulnerable/
    └── README.md                ← target repo index
```

## Quick start

### Prerequisites

- `bash` 4+, `awk`, `grep` (standard on any Unix system)
- [`gh` CLI](https://cli.github.com/) authenticated with a GitHub account (for runtime detection and live verification)
- Write access to the `turla-lab-targets` org repos (for running attacks; not required for detection or verification)

### Run the detection scanners

```bash
# Scenario 01 — scan a local repo for the pwn request pattern
./detections/01-pwn-request/detect.sh static /path/to/repo

# Scenario 02 — scan for script injection in workflow files
./detections/02-script-injection/detect.sh static /path/to/repo

# Runtime mode — query the GitHub Actions API
./detections/01-pwn-request/detect.sh runtime owner/repo --days 30
```

### Run the verification tests

```bash
# Verify scenario 01 hardening (offline, no live repo needed)
./verify/01-pwn-request/verify.sh static

# Verify scenario 02 hardening
./verify/02-script-injection/verify.sh static
```

### Scan your own repos

The detection scripts work against any GitHub Actions repository. Point them at your own projects to check for the same vulnerability patterns:

```bash
# Check all your org's repos for pwn request patterns
for repo in $(gh repo list your-org --limit 100 --json nameWithOwner -q '.[].nameWithOwner'); do
  ./detections/01-pwn-request/detect.sh runtime "$repo" --days 90
done

# Static scan of a local checkout
./detections/02-script-injection/detect.sh static ~/projects/your-app
```

## Safety

- Vulnerable workflows live in **separate public repos** under the disposable [`turla-lab-targets`](https://github.com/turla-lab-targets) org — never in this repo, never next to real projects.
- **Every secret is a dummy value.** No real credential, token, or cloud account is used anywhere in this lab.
- Target repos are disabled/archived between test runs. Public repos can receive PRs from anyone, so they are only active during controlled demonstrations.
- Attack scripts target **only** the lab's own repos. Nothing here is a tool for attacking third-party infrastructure.

## Standards mapping

This lab maps each scenario to established security frameworks:

| Framework | Coverage |
|---|---|
| [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | CICD-SEC-1, 3, 4, 5, 6, 7, 9 |
| [MITRE ATT&CK](https://attack.mitre.org/) | T1059.004, T1195, T1195.001, T1195.002, T1552 |
| [SLSA](https://slsa.dev/) | Build Level 2–3 targeted for hardened pipelines |
| [Sigma](https://sigmahq.io/) | Detection rules follow the Sigma specification |

## Per-scenario documentation

Each scenario has its own documentation at four levels of detail:

| Level | Location | Contents |
|---|---|---|
| Attack | `attacks/<id>/README.md` | Vulnerability description, attack surface, evidence, MITRE/OWASP mapping |
| Detection | `detections/<id>/README.md` | Sigma rule explanation, scanner usage, false-positive handling, limitations |
| Hardening | `hardened/<id>/README.md` | Before/after comparison, architecture diagram, standards mapping, deployment steps |
| Verification | `verify/<id>/README.md` | What is verified, how to run it, exit codes |

## Roadmap

- [x] Scenario 03 — Secret exfiltration
- [ ] Scenario 04 — Mutable action tag hijack
- [ ] Scenario 05 — Cache poisoning
- [ ] Scenario 06 — Artifact tampering
- [ ] Unified CI workflow that runs all verification suites on every push
- [ ] Jenkins phase 2 (separate top-level folder or repo)

## License

This project is intended for educational and defensive security research purposes only.
