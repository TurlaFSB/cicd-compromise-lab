# Live target-org testing runbook — scenarios 04–14

This runbook is the operator procedure for exercising each scenario **live**
against its disposable target repository in the
[`turla-lab-targets`](https://github.com/turla-lab-targets) org, as a
complement to the offline, self-contained loop recorded in
[`verification-evidence.md`](verification-evidence.md).

## Authorization and safety boundary

Run this **only** against the lab's own `turla-lab-targets` repositories, or
other systems you own and are explicitly authorized to test. Every secret in
every target is a dummy value; the payloads demonstrate access (e.g. printing a
secret's *length*), they do not exfiltrate to any real endpoint. Do not point
any step here at third-party infrastructure.

Between runs the target repos are kept **empty / archived** (verified: all
eleven 04–14 targets are currently empty). A live test therefore always starts
by deploying the scenario's vulnerable workflow and ends by restoring the repo
to empty.

## The five phases, per scenario

Each scenario follows the same loop. `<id>` is the scenario slug (e.g.
`08-env-injection`); `<target>` is its repo from
[`../vulnerable/README.md`](../vulnerable/README.md).

1. **Deploy vulnerable.** Push the files from `attacks/<id>/` into
   `turla-lab-targets/<target>` at the paths in `vulnerable/README.md`
   (`.github/workflows/…`, plus any `.npmrc` / `package.json` / `trust-policy.json`).
2. **Trigger.** Fire the scenario's trigger (table below) and let Actions run.
3. **Evidence.** Confirm the compromise in the run logs (the "look for" column),
   and that the detection scanner flags it live:
   `detections/<id>/detect.sh runtime turla-lab-targets/<target>`.
4. **Harden.** Replace the workflow(s) with the files from `hardened/<id>/`,
   re-trigger, and confirm the attack no longer succeeds and the scanner clears
   the repo.
5. **Verify + reset.** Run `./lab verify <id>` for the structural proof, then
   empty the target repo again.

## Per-scenario trigger / evidence matrix

| # | Target | Deploy from | Trigger | Look for (compromise) | Hardened expectation |
|---|--------|-------------|---------|-----------------------|----------------------|
| 04 | `tag-hijack-target` | `attacks/04-tag-hijack/vulnerable-ci.yml` + `payload/action.yml` as the hijacked `lab-helper-action@v1` | push to a branch running CI | telemetry step prints `DEPLOY_TOKEN`/`NPM_TOKEN`/`GITHUB_TOKEN` lengths — proves the retagged action ran with secrets in scope | SHA-pinned `hardened/04/ci.yml`: the retag no longer changes what runs |
| 05 | `cache-poisoning-target` | `attacks/05-cache-poisoning/pr-check.yml` + `release.yml` | open a PR (writer) then push to main (victim) | release build restores the PR-seeded `build-cache` entry and publishes poisoned content | `hashFiles()`-bound key, read-only restore on PR: no cross-restore |
| 06 | `artifact-tampering-target` | `attacks/06-artifact-tampering/release.yml` | push a tag | publish job ships bytes it never verified | provenance attest + `gh attestation verify`: tampered byte aborts publish |
| 07 | `runner-persistence-target` | `attacks/07-runner-persistence/ci.yml` | PR **(requires a self-hosted runner registered to the repo)** | implant dropped by job 1 survives into a later job on the reused runner | ephemeral/GitHub-hosted runner: implant gone |
| 08 | `env-injection-target` | `attacks/08-env-injection/triage.yml` | open an issue whose title carries the `payload/inject.txt` second line | run log shows `NODE_OPTIONS` set as an env var the author never wrote | step-scoped `env:`: no injected variable |
| 09 | `reusable-workflow-target` | `attacks/09-reusable-workflow/release.yml` | push a tag | caller runs an upstream `@main` reusable workflow with `secrets: inherit` | SHA-pinned call, named secrets only |
| 10 | `token-overprivilege-target` | `attacks/10-token-overprivilege/ci.yml` + `labeler.yml` + `triage.yml` | the matching trigger per file (`pull_request_target`, `issue_comment`) | effective `GITHUB_TOKEN` holds high-risk write scopes a compromised step inherits | read-only floor, per-job scopes |
| 11 | `workflow-run-poisoning-target` | `attacks/11-workflow-run-poisoning/build.yml` + `comment.yml` | PR from a fork **(requires a second account/fork)**, then the `workflow_run` handler | handler executes fork-controlled artifact code with base token/secrets | handler validates the PR number as data, executes nothing |
| 12 | `oidc-trust-target` | `attacks/12-oidc-trust-policy/deploy.yml`; apply `trust-policy.json` to a throwaway cloud role **(requires a cloud account you own)** | `pull_request_target` run | over-broad `sub` + missing `aud` admits a token beyond the intended identity | pinned `sub`+`aud`, `id-token: write` on one job |
| 13 | `artifact-cred-leak-target` | `attacks/13-artifact-cred-leak/release.yml` | push | downloaded artifact contains `.git/config` token and `.npmrc` token | `persist-credentials: false`, `env:` secret, `dist/`-only upload |
| 14 | `dependency-confusion-target` | `attacks/14-dependency-confusion/ci.yml` + `package.json` + `.npmrc` | push **(full confusion also needs a public `@turla-lab/internal-utils@9.9.9` you publish to a registry you control)** | unpinned scope resolves the higher public version; `postinstall` runs at install time | `npm ci --ignore-scripts`, scope pinned in `.npmrc` |

## Notes on scope and prerequisites

Four scenarios need infrastructure beyond a single GitHub account and so are
only fully "live" with extra setup you provide and own:

- **07** needs a self-hosted runner registered to the target repo.
- **11** needs a fork PR, i.e. a second account or fork.
- **12** needs a throwaway cloud (AWS) role you own to carry the trust policy.
- **14**'s dependency-confusion half needs a public package of the internal
  name, at a higher version, published to a registry you control.

For every scenario, the **detection** and **hardening** halves, and the offline
simulation, are fully exercisable without that extra infrastructure — see
[`verification-evidence.md`](verification-evidence.md), which records the
offline loop passing 130/130 for 04–14.
