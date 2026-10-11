# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses dated milestones rather than semantic versions, since it is a lab and not a library.

## [Unreleased]

### Added
- `lab` command-line entry point: `list`, `scan` (local or remote repos, aggregated summary and exit code), `verify`, and `doctor`. Scenarios are auto-discovered.
- **Scenario 04 — mutable action tag hijack:** vulnerable workflow, five-vector scanner (`--skip-official` support), Sigma rule, SHA-pinned hardened workflow, 12 verification checks.
- Community health files: `LICENSE` (MIT), `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `CITATION.cff`.
- GitHub issue forms, pull request template, `CODEOWNERS`, and Dependabot configuration for GitHub Actions.
- CI workflow that runs every scenario's verification suite and `shellcheck` on each push and pull request.

### Changed
- Attack driver now commits as the maintainer's current identity; author email in captured scenario 01 evidence redacted.

### Planned
- Scenarios 04–07 (mutable action tag hijack, cache poisoning, artifact tampering, self-hosted runner persistence).
- Scenarios 08–10 (`GITHUB_ENV` injection, reusable workflow trust boundary, `GITHUB_TOKEN` over-privilege).
- Scenarios 11–14 (`workflow_run` artifact poisoning, OIDC trust misconfiguration, credential leakage via artifacts, dependency confusion).
- Unified scanner emitting SARIF, and an empirical scan of public repositories.

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
