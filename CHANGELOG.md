# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses dated milestones rather than semantic versions, since it is a lab and not a library.

## [Unreleased]

### Added
- **Scenario 10 — `GITHUB_TOKEN` over-privilege:** three vulnerable workflows (`write-all` on `pull_request_target`, no permissions block, high-risk write on `issue_comment`), a four-vector scanner built on a shared awk permissions parser, an effective-token simulation that maps each write scope to what it unlocks, Sigma rule, hardened workflows with a read-only floor and per-job grants, 15 verification checks.
- SARIF rule metadata (title and OWASP link) for scenarios 06–10 in `to_sarif.py`; previously they fell back to the default link.
- **Scenario 09 — reusable workflow trust boundary:** vulnerable caller using a mutable `@main` ref with `secrets: inherit`, three-vector scanner that separates job-level `uses:` from step-level actions, Sigma rule, hardened caller pinned by SHA with explicitly named secrets, 7 verification checks.
- **Scenario 08 — GITHUB_ENV / GITHUB_PATH injection:** vulnerable workflow writing untrusted issue text to the runner env files, three-vector scanner, an injection simulation (NODE_OPTIONS smuggled via GITHUB_ENV), Sigma rule, hardened workflow passing untrusted data via step-scoped `env:` with a safe heredoc cross-step pattern, 9 verification checks.
- **Scenario 07 — self-hosted runner persistence:** vulnerable workflow running untrusted PR code on a self-hosted runner, three-vector scanner, a persistence simulation (reused vs ephemeral runner), Sigma rule, hardened workflow on ephemeral GitHub-hosted runners, 9 verification checks.
- **Scenario 06 — artifact tampering:** vulnerable build→publish workflow (no integrity binding), three-vector scanner, a concrete tamper simulation (hash → tamper → verify), Sigma rule, hardened workflow using `actions/attest-build-provenance` + `gh attestation verify`, 10 verification checks.
- SARIF 2.1.0 output: `lab scan --format sarif` and a `sarif-file` input on the Action, so findings land on the exact workflow line in GitHub's Security tab with their rule and OWASP link. A dedicated converter (`detections/to_sarif.py`) maps each detector vector to a stable rule id; CI generates and validates a report for the fixture.
- **Scenario 05 — cache poisoning:** vulnerable writer/victim workflow pair, five-vector job-aware scanner, offline cache-scoping simulation, Sigma rule, hardened read-only/content-bound workflows, 12 verification checks.
- Composite GitHub Action (`action.yml`) that runs every scenario scanner on a repository, with per-finding annotations, a job summary, and a `findings` output. Covered by a self-test job in CI.
- `lab pin`: resolves action tags and branches to full commit SHAs, dry-run by default, idempotent, leaves unresolvable references untouched.
- `lab` command-line entry point: `list`, `scan` (local or remote repos, aggregated summary and exit code), `verify`, and `doctor`. Scenarios are auto-discovered.
- **Scenario 04 — mutable action tag hijack:** vulnerable workflow, five-vector scanner (`--skip-official` support), Sigma rule, SHA-pinned hardened workflow, 12 verification checks.
- Community health files: `LICENSE` (MIT), `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `CITATION.cff`.
- GitHub issue forms, pull request template, `CODEOWNERS`, and Dependabot configuration for GitHub Actions.
- CI workflow that runs every scenario's verification suite and `shellcheck` on each push and pull request.

### Fixed
- Action wrapper aborted on repositories with no findings because the runner starts composite shell steps with `errexit`; it now disables it explicitly.
- `SC2015` findings from ShellCheck 0.9 (the version on GitHub's Ubuntu runners) in the `live` argument checks of three verify scripts, which had kept the ShellCheck job red.
- `verify/01-pwn-request/verify.sh live` called an undefined `die` function on a usage error; it now prints usage and exits 2.

### Changed
- Attack driver now commits as the maintainer's current identity; author email in captured scenario 01 evidence redacted.

### Planned
- Scenarios 11–14 (`workflow_run` artifact poisoning, OIDC trust misconfiguration, credential leakage via artifacts, dependency confusion).
- An empirical scan of public repositories, compared against `zizmor` and `actionlint`.

## 2026-10-11

### Added
- **Scenario 03 — secret exfiltration:** vulnerable target, Sigma rule, six-vector scanner, hardened workflow, 14 verification checks.
- Rewritten top-level README, expanded threat model, and target repo index.

### Fixed
- Replaced non-portable `\s` with `[[:space:]]` in scenario 01 detection script.
- Corrected date in the scenario 02 Sigma rule.
- Run-block extraction in the scenario 03 scanner ignored content after blank lines, which hid a masking-bypass finding.

## Earlier

### Added
- **Scenario 02 — script injection:** scanner covering 20+ untrusted contexts, hardened workflow, 11 verification checks.
- **Scenario 01 — pwn request:** attack driver, captured evidence, scanner, split-job hardened workflow, 10 verification checks.
- Initial repository scaffold and threat model.
