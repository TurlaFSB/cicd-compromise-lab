# Hardened workflows — Scenario 05: Cache poisoning

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| PR workflow cache | Read-write `actions/cache` (fork can save) | Read-only `actions/cache/restore` (fork cannot save) |
| Cache key | `build-cache` (static, forgeable) | `npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}` |
| `restore-keys` | `build-` (fuzzy prefix) | none (exact match only) |
| Cached paths | `node_modules/`, `dist/` (executable) | `~/.npm` (downloads only) |
| Release build | Skips rebuild if dir restored | Always `npm ci` + `npm run build` |
| Release permissions | Workflow-level `contents: write` | Per-job `contents: read`, `packages: write` |
| Release gate | None | `environment: release` |

## Why each change matters

### 1. Read-only cache on untrusted triggers

The single most important fix. The PR workflow uses `actions/cache/restore`, which only reads. With no save step, a fork PR has no way to place content under *any* cache key. The write side of the trust boundary is closed.

### 2. Content-bound keys

Every key includes `hashFiles('**/package-lock.json')`. The key is now a function of committed repository content. An attacker cannot produce a matching key without committing the same lockfile — and any change to the lockfile changes the key. Even if a fork PR could write (it cannot, per fix 1), it could not occupy the key the release build restores.

### 3. No `restore-keys`

Fuzzy prefix matching (`restore-keys: build-`) lets an entry written under one key satisfy a restore for another. Removing it means only an exact, content-bound key match restores anything.

### 4. Cache downloads, not output

The cache holds `~/.npm` (the package download cache), never `node_modules/` or `dist/`. A poisoned download cache is still re-resolved against the lockfile by `npm ci`; poisoned build output would be executed directly. Caching only immutable downloads removes the executable-code path.

### 5. Always rebuild

The release workflow runs `npm ci` and `npm run build` unconditionally. The cache is a speed-up for downloads, never a substitute for building from source. Nothing restored from a cache is published without being rebuilt from the committed source.

### 6. Least privilege + environment gate

Per-job permissions (`contents: read`, `packages: write` only on the publish job) and an `environment: release` gate add defense in depth, matching the pattern from scenarios 03 and 04.

## Standards mapping

| Standard | Requirement | How this meets it |
|---|---|---|
| OWASP CICD-SEC-9 | Validate artifact integrity | Release builds from source every time; caches cannot inject content |
| SLSA Build L2–L3 | Hermetic, verifiable builds | Downloads keyed to the lockfile hash; build is reproducible from source |
| MITRE T1195.002 | Defend the software supply chain | Untrusted triggers cannot write a cache a trusted build consumes |

## Deployment

1. Replace the target repo's `pr-check.yml` and `release.yml` with the files here.
2. Configure a `release` environment in repo settings (required reviewers, branch restriction).
3. Verify: `./verify/05-cache-poisoning/verify.sh static` (12/12 checks).
4. Optionally run `actionlint` / `zizmor` as a CI gate.

## Verification

12 structural checks confirm the fix — scanner clears the hardened pair and flags the vulnerable pair, the simulation reports SAFE vs. POISONED, and seven structural invariants hold (read-only writer, hashFiles keys, no restore-keys, download-only paths, unconditional rebuild, per-job permissions + environment, SHA-pinned actions).
