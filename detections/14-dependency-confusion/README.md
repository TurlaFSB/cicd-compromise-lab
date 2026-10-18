# Detection — Scenario 14: dependency confusion / install-script abuse

## Sigma rule

[`dependency-confusion.yml`](dependency-confusion.yml) fires on a workflow definition that pipes a remote script into a shell, runs `npm install` (fresh resolution), or installs without `--ignore-scripts`.

## Scanner

[`detect.sh`](detect.sh) checks the workflow and the npm config. The npm manifest/registry half is parsed by [`npmcheck.py`](npmcheck.py).

| Vector | Where | What it catches |
|---|---|---|
| PIPE TO SHELL | workflow | `curl …\| sh`, `wget …\| bash` — a remote script run unverified |
| NO LOCKFILE INSTALL | workflow | `npm install` (not `npm ci`): versions resolved fresh, a higher public version can win |
| INSTALL SCRIPTS ENABLED | workflow | `npm`/`yarn`/`pnpm` install without `--ignore-scripts` |
| UNPINNED SCOPE | package.json + .npmrc | a scoped dependency (`@scope/…`) with no `@scope:registry=` pin in `.npmrc` |

### Usage

```bash
./detect.sh static  /path/to/repo      # scan workflows + package.json/.npmrc
./detect.sh runtime owner/repo         # workflows only, via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error. Requires `python3` for the npm-config half.

## npm-config discovery

In repo-scan mode the scanner finds `package.json` files up to two directory levels deep (skipping `node_modules`) and pairs each with the nearest `.npmrc` (same directory, else the repo root). This keeps a whole-repo scan from descending into vendored trees.

## False positives

| Source | Why it may be benign |
|---|---|
| `npm ci --ignore-scripts` with scopes pinned in `.npmrc` | The intended pattern — not flagged |
| A project that genuinely needs lifecycle scripts (native addons) | INSTALL SCRIPTS ENABLED fires; vet scripts another way and treat as accepted risk |
| `curl … -o file` then a separate verified run | Not a pipe-to-shell — not flagged |

## Limitations

- **Heuristic install matching.** The scanner matches `npm`/`yarn`/`pnpm` install invocations textually; an install wrapped in a custom script or Makefile target is not followed.
- **npm-focused confusion check.** `npmcheck.py` reasons about npm scopes and `.npmrc`. Python (`pip`/`--index-url`), RubyGems, and other ecosystems have the same confusion risk but are not parsed here.
- **Pin, not reachability.** UNPINNED SCOPE flags the missing registry pin; it does not confirm an attacker has actually registered the name publicly.
- **Parser scope.** Workflow matching is line-oriented and skips comment lines; an install split across continuation lines may be missed.
