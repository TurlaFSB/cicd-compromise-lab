# Scenario 13 — credential leakage via artifacts

**OWASP:** CICD-SEC-6 (Insufficient Credential Hygiene) · **MITRE ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files)

## Target

A single build-and-release workflow (`release.yml`) that leaks secrets into the artifact it uploads:

| File | Flaw |
|---|---|
| `release.yml` | checkout persists its token into `.git/config`; the npm token is written to `.npmrc`; the upload path is `.` with `include-hidden-files: true` |

## The vulnerability

Artifacts are meant for build output, but anyone who can download one gets *every* byte in it. On a public repository, artifacts are downloadable by anyone on the internet; on a private repository, by everyone with read access and by workflows that can reach the run. So whatever ends up in the uploaded tree is effectively published to that audience.

This workflow puts credentials there four different ways:

1. **Persisted checkout credential.** `actions/checkout` defaults to `persist-credentials: true`, which writes the job's `GITHUB_TOKEN` into `.git/config` as an `http.<host>.extraheader`. The token sits in the working tree for the rest of the job.
2. **Secret written to a file.** `echo "…${{ secrets.NPM_TOKEN }}" > .npmrc` materialises the npm token on disk.
3. **Broad upload path.** `path: .` uploads the entire working tree — build output *and* `.git/config` *and* `.npmrc`.
4. **Hidden files forced in.** `include-hidden-files: true` overrides upload-artifact's safe default and pulls dotfiles (`.git`, `.npmrc`, `.env`) into the archive.

The result: the `build-output` artifact contains both the checkout token and the npm token.

## Attack path

1. A build runs and uploads `build-output`.
2. Anyone who can download the artifact extracts it.
3. `.git/config` yields the checkout token; `.npmrc` yields the npm token.
4. The attacker uses the npm token to publish malicious package versions, or the checkout token (within its short life) to push to the repo.

## Simulation

[`simulate.sh`](simulate.sh) demonstrates the leak offline:

```bash
./simulate.sh                 # judge the vulnerable release.yml
./simulate.sh <workflow.yml>  # judge a specific workflow
```

Part 1 builds a workspace with a token in `.git/config` and `.npmrc`, archives it both ways (`path: .` + hidden files vs. `dist/` only), and greps each archive for the secret — the broad archive leaks, the narrow one does not. Part 2 inspects a workflow for the four patterns and reports `LEAKY` (exit 1) or `SAFE` (exit 0).

## Fix direction

See `hardened/13-artifact-cred-leak/`. Summary:

1. `persist-credentials: false` on checkout so the token never lands in `.git/config`.
2. Pass secrets through `env:` to the tool that needs them (e.g. `NODE_AUTH_TOKEN` for `npm publish`); never write them to a file.
3. Upload only the build output (`path: dist/`), never the tree.
4. Leave `include-hidden-files` at its default (false).
