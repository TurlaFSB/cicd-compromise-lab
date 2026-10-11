# Detection — Scenario 05: Cache poisoning

## Sigma rule

[`cache-poisoning.yml`](cache-poisoning.yml) fires on a workflow definition when a build cache can be written by an untrusted trigger and restored by a privileged one, or when the cache key is forgeable. It combines five conditions:

| Condition | Meaning |
|---|---|
| `uses_readwrite_cache` + `trigger_untrusted` | Read-write `actions/cache` on `pull_request(_target)` — a fork PR can seed the cache |
| `trigger_privileged` + `broad_restore_keys` | A push/release build with fuzzy `restore-keys` prefix matching |
| `static_key` and not `keyed_to_hash` | A cache key with no `hashFiles()` component — forgeable |
| `executable_paths` | Build output / binary directories (`dist`, `build`, `bin`, `target`) in the cache |

## Scanner

[`detect.sh`](detect.sh) implements the rule as a job-aware scanner. It inspects each workflow's `on:` triggers and cache steps and reports five vectors:

| Vector | What it catches |
|---|---|
| CACHE ON UNTRUSTED TRIGGER | Read-write `actions/cache` in a `pull_request(_target)` workflow |
| STATIC CACHE KEY | A `key:` with no `hashFiles()` component |
| BROAD RESTORE-KEYS | `restore-keys` present (fuzzy prefix matching) |
| EXECUTABLE PATHS CACHED | `dist/`, `build/`, `bin/`, `.venv`, `target/`, `node_modules/.bin` in the cache |

It also prints one **informational note** (not a finding, does not affect the exit code) when a privileged workflow restores a cache, so a reviewer can confirm no sibling workflow writes the same key.

### Usage

```bash
./detect.sh static  /path/to/repo      # scan local workflow files
./detect.sh runtime owner/repo         # fetch workflows via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error.

The scanner distinguishes read-write `actions/cache` from read-only `actions/cache/restore`: the read-only action on an untrusted trigger is safe and is not flagged for vector 1.

## Scan your own repos

```bash
for repo in $(gh repo list your-org --limit 100 --json nameWithOwner -q '.[].nameWithOwner'); do
  ./detect.sh runtime "$repo"
done
```

## False positives

| Source | Why it may be benign |
|---|---|
| PR workflow using `actions/cache/restore` (read-only) | Cannot write a cache; vector 1 does not fire on it |
| Download cache (`~/.npm`, `~/.cache/pip`) keyed to a lockfile hash | Not forgeable and not executable; no vector fires |
| Privileged build caching downloads with a content-bound key | Emitted as an informational NOTE, not a finding |
| Monorepo caching a build dir keyed to a full content hash | Verify the key cannot be forged by a fork PR, then accept |

## Limitations

- **Static view only.** The scanner reads workflow YAML. It cannot see whether two workflows that share a key actually run in the same repo with conflicting trust levels — it flags the ingredients and leaves the final judgement to a reviewer (hence the informational note).
- **No cross-workflow key correlation.** It does not yet match a writer workflow's key against a victim workflow's key across files; `attacks/05-cache-poisoning/simulate.sh` does that correlation for the lab's own pair.
- **Expression-level keys.** A key built from a complex expression is treated as content-bound only if it literally contains `hashFiles(`. A hash passed in through an intermediate variable would be missed.
