# Security policy

## Scope

This project is an educational and defensive security lab. It contains intentionally vulnerable workflow definitions (published in the separate `turla-lab-targets` organization), reproducible attack drivers, detection rules, and hardened reference workflows.

**Out of scope** (these are intentional, by design):

- The vulnerabilities in the `turla-lab-targets/*` repositories.
- The attack payloads and drivers under `attacks/`.
- The dummy secrets in the target repositories. Every credential in this lab is a placeholder with no access to any real system.

**In scope** — please report:

- A flaw in a **hardened** workflow under `hardened/` that still permits the attack it claims to prevent.
- A detection rule or scanner under `detections/` that can be bypassed by a trivial variation, or that executes untrusted input unsafely (for example, shell injection through a filename or workflow content scanned by `detect.sh`).
- A verification check under `verify/` that passes when it should fail.
- Any real credential, token, or personal data committed to this repository.
- Attack tooling that can be pointed at infrastructure outside the lab organization without an explicit opt-in.

## Reporting a vulnerability

Please **do not open a public issue** for in-scope security problems.

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/TurlaFSB/cicd-compromise-lab/security) of this repository.
2. Select **Report a vulnerability**.
3. Describe the issue, the affected file(s), and steps to reproduce.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within 5 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation for confirmed issues | within 30 days, depending on complexity |

Reporters who want credit will be named in the changelog and the published advisory. Please allow a fix to be released before public disclosure.

## Supported versions

Only the latest commit on `main` is supported. The lab is not versioned for production deployment.

## Responsible use

The attack material here exists so defenders can understand, detect, and prevent these techniques. Run it only against the lab's own repositories or systems you own and have explicit written authorization to test. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for conduct expectations.
