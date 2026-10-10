# cicd-compromise-lab

A reproducible lab that attacks GitHub Actions pipelines, detects the attacks, hardens the pipelines, and then proves the hardening works by re-running the same attacks and asserting they fail.

Every scenario follows the same loop:

```
vulnerable workflow -> reproducible attack -> evidence -> detection -> hardened workflow -> automated re-test
```

## Why this exists

CI/CD pipelines hold secrets, publish artifacts and deploy to production, which makes them one of the most valuable targets in a supply-chain attack. Public incidents (the 2025 `tj-actions/changed-files` compromise, SolarWinds-style build tampering) show the pattern. Most training material stops at "here is a vulnerable pipeline". This lab covers the full cycle: attack, detect, fix, verify.

## Scope (v1: GitHub Actions)

| # | Scenario | Primary risk (OWASP Top 10 CI/CD) |
|---|----------|-----------------------------------|
| 01 | Pwn request (`pull_request_target` checks out untrusted code) | CICD-SEC-4 Poisoned Pipeline Execution |
| 02 | Script injection via PR/issue title into `run:` | CICD-SEC-4, CICD-SEC-1 |
| 03 | Secret exfiltration from logs/env, long-lived credential | CICD-SEC-6 Insufficient Credential Hygiene |
| 04 | Mutable action tag hijack (`@v1` retagged) | CICD-SEC-3 Dependency Chain Abuse |
| 05 | Cache poisoning across workflows | CICD-SEC-9 Improper Artifact Integrity Validation |
| 06 | Artifact tampering between build and release | CICD-SEC-9 |
| 07 | Self-hosted runner persistence (stretch) | CICD-SEC-7 Insecure System Configuration |

Jenkins is a possible phase 2 and is out of scope for v1.

## Repository layout

```
.
├── attacks/       reproducible attack scripts and expected evidence, one folder per scenario
├── detections/    Sigma rules and log queries that catch each attack
├── hardened/      fixed versions of each workflow
├── verify/        CI that re-runs attacks against hardened workflows and asserts they fail
├── docs/          threat model, standards mapping, per-scenario write-ups
└── vulnerable/    pointer to the intentionally vulnerable target repos (see below)
```

## Lab architecture and safety rules

- The intentionally vulnerable workflows live in separate **public target repos under the throwaway org `turla-lab-targets`**, never in this repo and never next to real projects.
- Every secret in the lab is a dummy value. The exfiltration endpoint is lab-controlled. No real credential, token or cloud account is ever used anywhere in this lab.
- The vulnerable target repos are kept disabled/archived between test runs and only enabled while a scenario is actively being run, since public repos can receive PRs from strangers.
- Every attack is a script in `attacks/`, run against the lab's own repos only. Nothing here is a tool for attacking third-party infrastructure.

## Standards referenced

- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [MITRE ATT&CK](https://attack.mitre.org/) (technique IDs per scenario)
- [SLSA](https://slsa.dev/) (target: Build Level 3 for the hardened pipeline)

## Status

Early scaffold. See `docs/threat-model.md` for the full write-up as each scenario lands.
