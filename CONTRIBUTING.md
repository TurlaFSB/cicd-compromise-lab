# Contributing

Thanks for your interest in improving the CI/CD Pipeline Compromise Lab. Contributions that make the attacks more realistic, the detections more accurate, or the hardening more rigorous are welcome.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems in the project itself go through [SECURITY.md](SECURITY.md), not public issues.

## The scenario contract

Every scenario is a closed loop, and a scenario is only "complete" when all six parts exist and pass:

```
Vulnerable workflow → Reproducible attack → Evidence → Detection → Hardened workflow → Verification
```

| Part | Location | Requirement |
|---|---|---|
| Attack write-up | `attacks/NN-name/README.md` | Explains the mechanism, attacker capabilities, evidence, and OWASP / MITRE mapping |
| Detection | `detections/NN-name/` | A Sigma rule, a `detect.sh` supporting `static` and `runtime` modes, and a README covering false positives and limitations |
| Hardened workflow | `hardened/NN-name/` | A fixed workflow with comments explaining each change, plus a README with before/after |
| Verification | `verify/NN-name/verify.sh` | Offline structural checks, including a cross-check that the scanner flags the vulnerable workflow and clears the hardened one |
| Target repo entry | `vulnerable/README.md` | Row linking the vulnerable workflow in `turla-lab-targets` |
| Threat model entry | `docs/threat-model.md` | Technique, OWASP/ATT&CK mapping, impact, fix |

## Development setup

Requirements: `bash` 4+, `awk`, `grep`, and [`shellcheck`](https://www.shellcheck.net/). The `gh` CLI is only needed for runtime detection modes.

```bash
# Run every verification suite
for s in verify/*/verify.sh; do "$s" static || exit 1; done

# Lint all shell scripts
shellcheck detections/*/detect.sh verify/*/verify.sh
```

Both commands run in CI on every push and pull request. Please run them locally first.

## Coding standards

**Shell scripts**

- Start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Must pass `shellcheck` with no warnings.
- Use POSIX character classes in `awk`/`grep` (`[[:space:]]`, not `\s`) so scripts run on both GNU and BSD/macOS tools.
- Avoid `((VAR++))` under `set -e` (it exits when the value is 0); use `VAR=$((VAR + 1))`.
- Exit codes: `0` clean, `1` finding or failure, `2` usage or dependency error.

**Workflows**

- Pin every third-party action to a full 40-character commit SHA with the tag in a trailing comment. Verify the SHA against the upstream tag; do not copy it from memory.
- Declare `permissions:` explicitly, least privilege, per job.
- Never place `${{ github.event.* }}` user-controlled values directly in `run:` blocks.

**Documentation**

- State limitations honestly. A detection that cannot catch a variant should say so.
- Every claim of the form "N/N checks pass" must be reproducible by running the script.

## Safety rules (non-negotiable)

- **No real credentials, ever.** Every secret in the lab is a dummy value. PRs containing anything resembling a real token will be closed and the history purged.
- Attack drivers may only target repositories in the `turla-lab-targets` organization. Do not add code that accepts an arbitrary external target without an explicit confirmation gate.
- Do not contribute weaponized payloads for real-world third-party software. Proof-of-concept evidence collection (for example, hashing a dummy secret) is preferred over destructive actions.

## Submitting changes

1. Open an issue first for anything larger than a typo or small fix, so scope can be agreed.
2. Fork and branch from `main` (`feat/scenario-04-tag-hijack`, `fix/detect-awk-portability`).
3. Keep commits focused. Use imperative-mood messages with a short summary line:
   `Add scenario 04 detection for mutable action tags`.
4. Open a pull request using the template. CI must pass.
5. A maintainer reviews. Expect requests for evidence (run output) on any change to a detection or verification rule.

## Proposing a new scenario

Open an issue using the **New scenario proposal** form. Include the real-world incident or research it is based on, the OWASP CI/CD risk and MITRE ATT&CK technique it maps to, and why it is distinct from the existing scenarios.

## Questions

Use [GitHub Discussions](https://github.com/TurlaFSB/cicd-compromise-lab/discussions) for questions and ideas, and issues for concrete bugs and proposals.
