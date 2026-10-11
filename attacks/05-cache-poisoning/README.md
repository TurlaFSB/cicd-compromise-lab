# Scenario 05 — Cache poisoning

**OWASP:** CICD-SEC-9 (Improper Artifact Integrity Validation) · **MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain)

## Target

A repo with two workflows that share a build cache:
- `pr-check.yml` — runs on `pull_request`, so it executes for fork PRs from anyone.
- `release.yml` — runs on push to `main` and on release, and publishes an artifact.

## The vulnerability

GitHub Actions caches are **scoped by Git ref**, but not isolated between trusted and untrusted runs. The access rule that matters:

> A workflow run can restore caches created in its own branch, in the **base branch** of a pull request, and in the repository's **default branch**. A run on a branch cannot read caches from unrelated sibling branches — but every branch is a child of the default branch.

So a cache entry written by a run — including a fork PR's run — can be restored by a later run, as long as the keys match. If a privileged workflow (push to `main`, release) restores a key that an untrusted workflow (`pull_request`) can write, an external contributor can inject content into the trusted build **without merging anything**.

### The two halves of the bug

| File | Role | Flaw |
|---|---|---|
| `pr-check.yml` | Writer | Read-write `actions/cache` runs on `pull_request`. Fork code decides what is saved under the key. |
| `release.yml` | Victim | Restores the same key (plus a fuzzy `restore-keys: build-` prefix) and skips a clean rebuild if the directory exists. |

The shared key is static (`build-cache`, no `hashFiles()`), and the cached paths include `node_modules/` and `dist/` — executable code, not just downloads.

### Attack path

1. Attacker forks the repo and opens a PR. `pr-check.yml` runs their code.
2. Their build step writes a tampered file into `dist/` (see `payload/poison.js`), and the job saves the cache under `build-cache` at the end.
3. On the next push to `main`, `release.yml` restores `build-cache`, finds `dist/` already present, skips the rebuild, and publishes an artifact containing the attacker's file.
4. The poisoned artifact reaches every downstream consumer of the release.

No approval, no review, no merge of the attacker's code is required — only that their PR workflow ran once and populated the key.

## Why cache scoping makes this work

The attacker cannot read the release build's secrets directly. What they can do is leave something behind in a shared cache that the privileged build trusts. The trust boundary that should exist between "code from a fork" and "the release pipeline" does not extend to the cache, because the cache key is the only thing deciding what gets restored — and the key is forgeable.

## Simulation

Because the attack depends on GitHub's cache-scoping rules rather than on log output, `simulate.sh` models those rules offline. It reads both workflow files, extracts each cache key and `restore-keys`, and decides — by GitHub's actual matching rules — whether the release build would restore an entry the fork PR can write.

```bash
./simulate.sh                                   # vulnerable pair: POISONED (exit 1)
./simulate.sh ../../hardened/05-cache-poisoning/pr-check.yml \
              ../../hardened/05-cache-poisoning/release.yml   # hardened: SAFE (exit 0)
```

Against the vulnerable pair it reports `POISONED` (exact key match on `build-cache`). Against the hardened pair it reports `SAFE`, because the key is bound to `hashFiles()` and the writer is read-only.

## Payload

`payload/poison.js` is a benign stand-in. It writes a `.poison-marker` file and prints a notice proving the restored-cache path was executed. It does not touch the network, read secrets, or modify anything outside the build directory.

## Fix direction

See `hardened/05-cache-poisoning/`. Summary:

1. **Read-only on untrusted triggers**: the PR workflow uses `actions/cache/restore` (no save step), so a fork PR can never write a cache entry.
2. **Content-bound keys**: every key includes `hashFiles('**/package-lock.json')`, so the key cannot be forged without changing the committed lockfile (which changes the key).
3. **No `restore-keys`**: only an exact, content-bound key matches — no fuzzy prefix fallback.
4. **Cache downloads, not output**: cache `~/.npm` only, never `node_modules/` or `dist/`.
5. **Always rebuild**: the release workflow runs `npm ci` and `npm run build` unconditionally; the cache only speeds up downloads and can never substitute for the build.
