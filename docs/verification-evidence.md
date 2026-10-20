# Verification evidence — scenarios 04–14

This is a reproducible record of a full local test run of the lab's closed
loop (vulnerable → attack simulation → detection → hardening → verification)
for scenarios 04 through 14. It documents what was executed, the expected
result, and the observed result, so the claims in the top-level
[`README.md`](../README.md) can be independently re-derived.

All testing here is **self-contained and offline**: it runs against the
workflow files, simulations, and scanners shipped in this repository. No live
attack is launched against any GitHub repository, and no network target is
touched. The live target repositories under the `turla-lab-targets` org (see
[`../vulnerable/README.md`](../vulnerable/README.md)) are a separate,
operator-driven exercise and are out of scope for this automated evidence run.

| Field | Value |
|---|---|
| Lab version (`VERSION`) | `0.1.0` |
| Scope | Scenarios 04–14 |
| Environment | `bash`, `awk`, `grep`, `sed`, `git`, `gh` present; `shellcheck` optional |
| Test classes | Structural verification · Attack simulation · Detection cross-check · Repo self-scan |

## How to reproduce

```bash
./lab doctor                 # confirm required tools
./lab verify                 # all scenarios (or: ./lab verify 04 … 14)
./lab scan .                 # self-scan: this repo's own workflows must be clean
python3 tests/check_links.py # markdown link + anchor check
# offline attack simulations:
for s in 05 06 07 08 10 11 12 13 14; do bash attacks/$s-*/simulate.sh; done
```

## 1. Structural verification (`./lab verify <id>`)

Each suite asserts the hardened workflow carries the specific structural
properties that defeat its attack, and cross-checks that the detection scanner
flags the vulnerable workflow and clears the hardened one.

| # | Scenario | Checks | Result |
|---|----------|-------:|--------|
| 04 | tag-hijack | 13/13 | PASS |
| 05 | cache-poisoning | 12/12 | PASS |
| 06 | artifact-tampering | 11/11 | PASS |
| 07 | runner-persistence | 9/9 | PASS |
| 08 | env-injection | 9/9 | PASS |
| 09 | reusable-workflow | 7/7 | PASS |
| 10 | token-overprivilege | 15/15 | PASS |
| 11 | workflow-run-poisoning | 11/11 | PASS |
| 12 | oidc-trust-policy | 14/14 | PASS |
| 13 | artifact-cred-leak | 14/14 | PASS |
| 14 | dependency-confusion | 15/15 | PASS |
| | **Total** | **130/130** | **PASS** |

## 2. Attack simulations (`attacks/<id>/simulate.sh`)

Each simulation demonstrates the mechanism concretely, then renders a verdict
for the vulnerable config and contrasts it with the hardened behaviour. A
non-zero exit is the intended signal that the vulnerable configuration is
exploitable.

| # | Scenario | Vulnerable verdict | Hardened behaviour |
|---|----------|--------------------|--------------------|
| 05 | cache-poisoning | POISONED (exact key match on `build-cache`) | SAFE — key bound to `hashFiles()`, read-only restore |
| 06 | artifact-tampering | TAMPERABLE (nothing binds build output to publish) | digest MISMATCH → publish ABORTED |
| 07 | runner-persistence | PERSISTS (untrusted PR code on self-hosted runner) | ephemeral runner → implant gone |
| 08 | env-injection | INJECTABLE (`NODE_OPTIONS` smuggled via `$GITHUB_ENV`) | no injected variables |
| 10 | token-overprivilege | OVER-PRIVILEGED (high-risk write reachable from untrusted trigger) | least-privilege floor, per-job scopes |
| 11 | workflow-run-poisoning | POISONABLE (blind consumer executed planted code) | validating consumer read PR number as data |
| 12 | oidc-trust-policy | EXPLOITABLE (over-broad subject, no `aud`) | subject + audience pinned |
| 13 | artifact-cred-leak | LEAKY (secret present in broad-path artifact) | narrow `dist/` upload → no secret |
| 14 | dependency-confusion | VULNERABLE (public `9.9.9` wins; `postinstall` ran) | `npm ci --ignore-scripts`, scope pinned |

## 3. Detection cross-check (`detections/<id>/detect.sh static`)

Each scanner was run against the scenario's vulnerable workflow(s) and its
hardened workflow(s), staged into a `.github/workflows/` layout.

| # | Scenario | Vulnerable | Hardened |
|---|----------|------------|----------|
| 04 | tag-hijack | FLAGGED | clean |
| 05 | cache-poisoning | FLAGGED | clean |
| 06 | artifact-tampering | FLAGGED | clean |
| 07 | runner-persistence | FLAGGED | clean |
| 08 | env-injection | FLAGGED | clean |
| 09 | reusable-workflow | FLAGGED | clean |
| 10 | token-overprivilege | FLAGGED | clean |
| 11 | workflow-run-poisoning | FLAGGED | clean |
| 12 | oidc-trust-policy | FLAGGED | clean |
| 13 | artifact-cred-leak | FLAGGED | clean |
| 14 | dependency-confusion | FLAGGED | clean |

## 4. Repository hygiene

| Check | Command | Result |
|---|---|---|
| Own workflows clean | `./lab scan .` | 14 scanners run, 0 flagged, 0 errored |
| Markdown links / anchors | `python3 tests/check_links.py` | 0 broken |
| Python helpers compile | `python3 -m py_compile detections/to_sarif.py detections/*/*.py tests/check_links.py` | OK |

## Conclusion

For scenarios 04–14 the full defensive loop holds: the vulnerable
configuration is demonstrably exploitable, the detection scanner flags it, the
hardened configuration carries the structural fix, the scanner clears the
hardened configuration, and the attack simulation confirms the fix defeats the
mechanism. 130/130 structural checks pass and the repository's own workflows
scan clean.
