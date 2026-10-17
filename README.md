# CI/CD Pipeline Compromise Lab

[![CI](https://github.com/TurlaFSB/cicd-compromise-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/TurlaFSB/cicd-compromise-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OWASP CI/CD Top 10](https://img.shields.io/badge/OWASP-CI%2FCD%20Top%2010-orange.svg)](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Sigma](https://img.shields.io/badge/detections-Sigma-informational.svg)](https://sigmahq.io/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

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
| 04 | [Mutable action tag hijack](#scenario-04--mutable-action-tag-hijack) | CICD-SEC-3 | T1195.001 | Complete |
| 05 | [Cache poisoning](#scenario-05--cache-poisoning) | CICD-SEC-9 | T1195.002 | Complete |
| 06 | [Artifact tampering](#scenario-06--artifact-tampering) | CICD-SEC-9 | T1195 | Complete |
| 07 | Self-hosted runner persistence | CICD-SEC-7 | T1053, T1547 | Planned |
| 08 | `GITHUB_ENV` / `GITHUB_PATH` injection | CICD-SEC-4 | T1574 | Planned |
| 09 | Reusable workflow trust boundary | CICD-SEC-3, CICD-SEC-4 | T1195.001 | Planned |
| 10 | `GITHUB_TOKEN` over-privilege | CICD-SEC-5, CICD-SEC-2 | T1078.004 | Planned |
| 11 | `workflow_run` artifact poisoning | CICD-SEC-4 | T1195 | Planned |
| 12 | OIDC trust policy misconfiguration | CICD-SEC-2, CICD-SEC-5 | T1078.004 | Planned |
| 13 | Credential leakage via artifacts | CICD-SEC-6 | T1552.001 | Planned |
| 14 | Dependency confusion and install-script abuse | CICD-SEC-3 | T1195.001 | Planned |

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

A workflow references third-party actions by mutable tags (`uses: org/action@v1`). If any tag is force-pushed upstream — by a malicious maintainer, a compromised account, or a supply-chain attacker — the next workflow run silently executes the new code with full access to `GITHUB_TOKEN` and all secrets in scope. The scanner detects five mutable reference types: version tags, branch refs, special tags, short SHAs, and missing refs.

**Fix:** Pin every third-party action to a full 40-character commit SHA. Use Dependabot to receive automated PRs when upstream publishes new versions. Set `persist-credentials: false` on checkout steps. Apply per-job least-privilege permissions and environment protection on deploy jobs.

**Verification:** 12/12 structural checks pass. Detection scanner correctly flags all 11 mutable references in the vulnerable workflow and clears the hardened one.

### Scenario 05 — Cache poisoning

Two workflows share a build cache: one runs on `pull_request` (fork PRs), the other on push/release. The shared key is static (`build-cache`, no `hashFiles()`), the PR workflow can write it, and the release workflow restores it — including `node_modules/` and `dist/` — then skips a clean rebuild. A fork PR seeds the cache with tampered content that the release build publishes, with no merge required. GitHub's cache scoping lets a fork PR's entry be restored by the default-branch build.

**Fix:** Read-only `actions/cache/restore` on untrusted triggers, keys bound to `hashFiles()` of the lockfile, no `restore-keys`, cache only downloads (`~/.npm`) not build output, and always rebuild from source in the release job. An offline cache-scoping simulation (`attacks/05-cache-poisoning/simulate.sh`) proves the vulnerable pair is poisonable and the hardened pair is not.

**Verification:** 12/12 structural checks pass. Scanner catches five vectors on the vulnerable pair and clears the hardened one; simulation reports POISONED vs. SAFE.

### Scenario 06 — Artifact tampering

A build job uploads `dist/` and a publish job downloads and ships it — with nothing binding the build output to the published bytes. `actions/upload-artifact`/`download-artifact` carry no integrity guarantee, so any actor able to write the artifact between the two jobs (a compromised step, a shared runner, a second workflow, or a fork's run in the `workflow_run` pattern) can swap the bytes and have them published under the project's real name.

**Fix:** `actions/attest-build-provenance` signs a SLSA build-provenance attestation over the artifact in the build job; the publish job runs `gh attestation verify` (plus a SHA-256 re-check) before publishing, so a tampered byte fails verification and is never shipped. A tamper simulation (`attacks/06-artifact-tampering/simulate.sh`) demonstrates the mechanism and proves the vulnerable workflow is tamperable and the hardened one is not.

**Verification:** 10/10 structural checks pass. Scanner catches the unverified-publish and no-provenance vectors on the vulnerable workflow and clears the hardened one; simulation reports TAMPERABLE vs. SAFE.

## Architecture

Every scenario repeats the same four-folder layout, so the tree below shows
one scenario in full and lists the rest. `<id>` is the scenario slug, e.g.
`01-pwn-request` or `05-cache-poisoning`.

```
cicd-compromise-lab/
├── lab                          ← single CLI entry point (list/scan/pin/verify/doctor)
├── action.yml                   ← reusable GitHub Action wrapper (scan on every PR)
├── VERSION                      ← tool version stamped into SARIF output
│
├── attacks/<id>/                ← the vulnerable workflow(s), attack driver, payload, evidence
│   └── README.md                  vulnerability write-up, attack path, MITRE/OWASP mapping
├── detections/
│   ├── to_sarif.py              ← findings → SARIF 2.1.0 converter (GitHub code scanning)
│   └── <id>/
│       ├── <name>.yml           ← Sigma rule
│       ├── detect.sh            ← static + runtime scanner
│       └── README.md              scanner usage, false positives, limitations
├── hardened/<id>/               ← the fixed workflow(s)
│   └── README.md                  before/after, defense layers, standards mapping
├── verify/<id>/
│   ├── verify.sh                ← structural checks + detection cross-check
│   └── README.md                  what is verified, how to run, exit codes
│
├── scenarios: 01-pwn-request  02-script-injection  03-secret-exfil
│              04-tag-hijack   05-cache-poisoning   06-artifact-tampering  (07+ planned)
│
├── docs/threat-model.md         ← system under test, trust boundaries, scenario catalog
├── tests/fixtures/              ← known-vulnerable workflow used by the action self-test
├── .github/                     ← CI, issue forms, PR template, CODEOWNERS, Dependabot
├── CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md  CHANGELOG.md  CITATION.cff  LICENSE
└── vulnerable/README.md         ← target repo index (turla-lab-targets org)
```

Vulnerable workflows live in separate repos under the `turla-lab-targets`
org (see `vulnerable/README.md`), never in this repo.

## Quick start

The `lab` script is the single entry point for everything below:

```bash
./lab doctor                    # check required tools
./lab list                      # scenarios and what each one ships
./lab scan /path/to/your/repo   # run every scenario scanner against a local repo
./lab scan --repo owner/repo    # same, against a remote repo (needs gh)
./lab scan /path --format sarif # emit SARIF 2.1.0 for GitHub code scanning
./lab verify                    # prove every hardened workflow resists its attack
./lab verify 04                 # ...or just one scenario
./lab pin /path/to/your/repo    # resolve action tags to commit SHAs (diff first)
```

`./lab scan` exits `1` when any scanner reports a finding, so it drops straight into CI as a gate. Scenario scanners are discovered automatically, so new scenarios appear in `list`, `scan` and `verify` with no extra wiring.

### Protect your own repository

**Scan every pull request** by adding the lab as a step in your workflow. Pin it to a full commit SHA, like any other third-party action:

```yaml
# .github/workflows/lab-scan.yml
name: Workflow security scan
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: TurlaFSB/cicd-compromise-lab@<full-commit-sha>
        with:
          skip-official: "false"     # also flag actions/* and github/*
          fail-on-findings: "true"   # fail the check when anything is found
```

Findings appear as annotations on the run and in the job summary. The step output `findings` holds the number of scanners that reported something.

**See findings in the Security tab** by asking the action for a SARIF report and handing it to GitHub's code-scanning upload. SARIF is the standard interchange format that puts each finding on the exact workflow line, with its rule and OWASP link:

```yaml
name: Workflow security scan
on: [pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: TurlaFSB/cicd-compromise-lab@<full-commit-sha>
        with:
          sarif-file: cicd-lab.sarif
          fail-on-findings: "false"   # let the upload run; the Security tab is the gate
      - uses: github/codeql-action/upload-sarif@<full-commit-sha> # vX
        with:
          sarif_file: cicd-lab.sarif
```

You can also generate SARIF locally: `./lab scan /path/to/repo --format sarif -o out.sarif`.

**Fix unpinned actions** with `lab pin`, which resolves every tag or branch reference to its full commit SHA and keeps the tag as a comment:

```bash
./lab pin /path/to/your/repo           # dry run: prints a diff, changes nothing
./lab pin /path/to/your/repo --write   # apply the change
```

Pinning locks in whatever each tag points at *right now*. If an upstream tag was already tampered with, you would pin the bad commit, so review the diff first. References that cannot be resolved are left unchanged and make the command exit non-zero. Fixes for script injection and pwn requests are deliberately not automated, because they need a human to decide what the workflow should do; the scanner points at the hardened example instead.

> The scanners are pattern-based (grep and awk). They will miss things and occasionally flag harmless code. Treat them as a teaching tool and a first-pass gate, and run [`zizmor`](https://github.com/woodruffw/zizmor) or [`actionlint`](https://github.com/rhysd/actionlint) alongside them for deeper analysis.

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

- [x] Scenarios 01–06 with the full attack → detect → harden → verify loop
- [x] CI that runs every verification suite, `shellcheck`, and a self-scan on each push
- [x] Reusable GitHub Action wrapper and `lab pin` auto-fix for unpinned actions
- [ ] Scenario 07 — self-hosted runner persistence
- [ ] Scenarios 08–10 — `GITHUB_ENV` injection, reusable workflow trust, `GITHUB_TOKEN` over-privilege
- [x] Unified scanner (`lab scan`) across all scenarios, with SARIF output for GitHub code scanning
- [ ] Scenarios 11–14 — `workflow_run` poisoning, OIDC misconfiguration, artifact credential leakage, dependency confusion
- [ ] Empirical scan of public repositories and comparison against `zizmor` and `actionlint`
- [ ] Jenkins phase 2 (separate top-level folder or repo)

## Contributing

Contributions are welcome, from scanner false-positive reports to whole new scenarios. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the scenario contract and coding standards. Report security issues in the project itself privately, as described in [SECURITY.md](SECURITY.md). All participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Citation

If you use this lab in research, teaching, or tooling, please cite it using [CITATION.cff](CITATION.cff) (GitHub's **Cite this repository** button).

## License

Released under the [MIT License](LICENSE). The attack material is provided for education and defensive research. Use it only against the lab's own repositories or systems you own and are explicitly authorized to test.
