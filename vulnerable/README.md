# Vulnerable target repos

Each scenario's intentionally vulnerable workflow lives in a separate public repo under the [`turla-lab-targets`](https://github.com/turla-lab-targets) GitHub organization. They are kept isolated from this repo so that a misconfigured workflow can never affect the lab's own CI/CD.

**Every secret in every target repo is a dummy value. No real credentials are used anywhere.**

## Demonstration method per scenario

Each scenario is validated in one of two ways, chosen by what can be shown safely and reproducibly:

- **Live** — the attack is executed against a real, intentionally-vulnerable target repo under [`turla-lab-targets`](https://github.com/turla-lab-targets), and the captured GitHub Actions run (metadata + logs) is stored under `attacks/<scenario>/evidence/`.
- **Simulation** — the attack mechanism is reproduced offline by `attacks/<scenario>/simulate.sh`, which models the GitHub behaviour deterministically. This is used where a faithful live demo would require infrastructure outside a single GitHub account (a self-hosted runner, a cloud IAM account) or an irresponsible act (publishing a confusable package to a public registry). Simulation is also the reproducibility backbone: it runs in CI with no external dependencies.

The `Status` column records the current state. A `—` target repo link means that target has not been provisioned yet; the scenario is covered by its in-repo vulnerable fixture, scanner, hardened workflow, verification suite, and (where present) simulation.

| Scenario | Target repo | Vulnerable workflow | Trigger | Status |
|---|---|---|---|---|
| 01 — Pwn request | [`pwn-request-target`](https://github.com/turla-lab-targets/pwn-request-target) | `.github/workflows/ci.yml` | `pull_request_target` | **Live — evidence captured** |
| 02 — Script injection | [`script-injection-target`](https://github.com/turla-lab-targets/script-injection-target) | `.github/workflows/triage.yml` | `issues: opened` | **Live — evidence captured** |
| 03 — Secret exfiltration | `secret-exfil-target` (—) | `.github/workflows/deploy.yml` | `push` / `pull_request` | Fixture + scanner + verify |
| 04 — Mutable action tag hijack | [`tag-hijack-target`](https://github.com/turla-lab-targets/tag-hijack-target) | `.github/workflows/ci.yml` | `push` / `pull_request` | Target provisioned; live run pending |
| 05 — Cache poisoning | `cache-poisoning-target` (—) | `.github/workflows/pr-check.yml` + `release.yml` | `pull_request` / `push` | Simulation |
| 06 — Artifact tampering | `artifact-tampering-target` (—) | `.github/workflows/release.yml` | `push` (tags) | Simulation |
| 07 — Self-hosted runner persistence | `runner-persistence-target` (—) | `.github/workflows/ci.yml` | `pull_request` | Simulation (live needs a self-hosted runner) |
| 08 — GITHUB_ENV / GITHUB_PATH injection | `env-injection-target` (—) | `.github/workflows/triage.yml` | `issues: opened` | Simulation |
| 09 — Reusable workflow trust boundary | `reusable-workflow-target` (—) | `.github/workflows/release.yml` | `push: tags` | Fixture + scanner + verify |
| 10 — GITHUB_TOKEN over-privilege | `token-overprivilege-target` (—) | `.github/workflows/ci.yml` | `pull_request_target` | Simulation |
| 11 — workflow_run artifact poisoning | `workflow-run-poisoning-target` (—) | `.github/workflows/build.yml` + `comment.yml` | `pull_request` / `workflow_run` | Simulation |
| 12 — OIDC trust policy misconfiguration | `oidc-trust-target` (—) | `.github/workflows/deploy.yml` + cloud-side `trust-policy.json` | `pull_request_target` | Simulation (live needs a cloud IAM account) |
| 13 — Credential leakage via artifacts | `artifact-cred-leak-target` (—) | `.github/workflows/release.yml` | `push` | Simulation |
| 14 — Dependency confusion / install-script abuse | `dependency-confusion-target` (—) | `.github/workflows/ci.yml` + `.npmrc` + `package.json` | `push` / `pull_request` | Simulation (live would require publishing to a public registry — deliberately not done) |

## Safety rules

- Target repos are **public** so GitHub Actions works on the free plan, but they are kept disabled/archived between test runs.
- Target repos contain no production code, no real secrets, and no branch protection rules that could be bypassed for real damage.
- Every attack is run from `attacks/` in **this** repo against the target repos only.
- No attack touches any system outside the `turla-lab-targets` organization. No package is published to any public registry. No real cloud credentials are issued or used.
