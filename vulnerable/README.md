# Vulnerable target repos

Each scenario's intentionally vulnerable workflow lives in a separate public repo under the [`turla-lab-targets`](https://github.com/turla-lab-targets) GitHub organization. They are kept isolated from this repo so that a misconfigured workflow can never affect the lab's own CI/CD.

**Every secret in every target repo is a dummy value. No real credentials are used anywhere.**

| Scenario | Target repo | Vulnerable workflow | Trigger |
|---|---|---|---|
| 01 — Pwn request | [`turla-lab-targets/pwn-request-target`](https://github.com/turla-lab-targets/pwn-request-target) | `.github/workflows/ci.yml` | `pull_request_target` |
| 02 — Script injection | [`turla-lab-targets/script-injection-target`](https://github.com/turla-lab-targets/script-injection-target) | `.github/workflows/triage.yml` | `issues: opened` |
| 03 — Secret exfiltration | `turla-lab-targets/secret-exfil-target` | `.github/workflows/deploy.yml` | `push` / `pull_request` |
| 04 — Mutable action tag hijack | `turla-lab-targets/tag-hijack-target` | `.github/workflows/ci.yml` | `push` / `pull_request` |
| 05 — Cache poisoning | TBD | TBD | TBD |
| 06 — Artifact tampering | TBD | TBD | TBD |

## Safety rules

- Target repos are **public** so GitHub Actions works on the free plan, but they are kept disabled/archived between test runs.
- Target repos contain no production code, no real secrets, and no branch protection rules that could be bypassed for real damage.
- Every attack is run from `attacks/` in **this** repo against the target repos only.
