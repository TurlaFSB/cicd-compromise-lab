# Scenario 14 — dependency confusion and install-script abuse

**OWASP:** CICD-SEC-3 (Dependency Chain Abuse) · **MITRE ATT&CK:** T1195.001 (Compromise Software Dependencies and Development Tools)

## Target

The install phase of a Node CI job, across three files:

| File | Flaw |
|---|---|
| `ci.yml` | pipes a remote script into a shell; runs `npm install` (fresh resolution) with lifecycle scripts enabled |
| `.npmrc` | sets a default registry but does **not** pin the `@turla-lab` scope to the internal registry |
| `package.json` | depends on `@turla-lab/internal-utils` — an internal package whose scope is unpinned |

## The vulnerability

Installing dependencies is the moment CI runs the most third-party code. Two classic supply-chain attacks live here, and this job is open to both.

**Dependency confusion.** `@turla-lab/internal-utils` is an internal package served from a private registry. Because `.npmrc` never pins the `@turla-lab` scope to that registry, npm resolves the scope against the public registry too. An attacker publishes a package of the *same name* publicly at a higher version (`9.9.9`), and `npm install` — which resolves versions fresh — prefers it. The build now runs the attacker's code as that dependency.

**Install-script abuse.** `npm install` (and `npm ci`) run each dependency's `preinstall`/`install`/`postinstall` lifecycle scripts by default. A malicious or confused package therefore executes arbitrary code at install time, before any test or review. `--ignore-scripts` is absent here, so nothing stops it.

**Pipe to shell.** On top of that, `curl … | sh` runs whatever the bootstrap server returns at that moment — no pinned version, no checksum, no review. If that server (or the connection) is compromised, so is the runner.

## Attack path

1. Attacker publishes `@turla-lab/internal-utils@9.9.9` to the public npm registry.
2. CI runs `npm install`; with the scope unpinned, the public `9.9.9` outranks the internal `1.2.0`.
3. npm runs the malicious package's `postinstall` — attacker code executes in CI with the job's environment.
4. (Independently) the `curl | sh` step runs whatever `install.example.test` serves.

## Simulation

[`simulate.sh`](simulate.sh) demonstrates both mechanisms offline:

```bash
./simulate.sh                 # judge this directory (vulnerable)
./simulate.sh <dir>           # judge a scenario directory
```

Part 1 shows resolution picking the public `9.9.9` when the scope is unpinned (and staying internal when pinned), and a dependency `postinstall` executing when scripts are enabled (and not when `--ignore-scripts` is set). Part 2 inspects the directory and reports `VULNERABLE` (exit 1) or `SAFE` (exit 0).

## Fix direction

See `hardened/14-dependency-confusion/`. Summary:

1. `npm ci --ignore-scripts` — install locked versions, run no lifecycle scripts.
2. Pin internal scopes in `.npmrc`: `@turla-lab:registry=https://<internal>`, and set `ignore-scripts=true`.
3. Never pipe the network into a shell — download, verify a pinned checksum, then run.
4. Commit `package-lock.json` so `npm ci` has an exact graph to install.
