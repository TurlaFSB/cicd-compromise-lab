# Hardened install phase — Scenario 14: dependency confusion / install-script abuse

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Install command | `npm install` | `npm ci --ignore-scripts` |
| Lifecycle scripts | run | disabled (flag + `.npmrc`) |
| Internal scope | unpinned (resolves publicly) | `@turla-lab:registry=https://npm.internal…` |
| Remote bootstrap | `curl … \| sh` | download → `sha256sum --check` → run |
| Lockfile | ignored | `npm ci` requires `package-lock.json` |

## Why each change works

### 1. `npm ci` instead of `npm install`

```yaml
- name: Install dependencies
  run: npm ci --ignore-scripts
```

`npm ci` installs exactly what `package-lock.json` records and errors if the lockfile and manifest disagree. There is no fresh version resolution, so an attacker's higher-versioned public package cannot be substituted for a locked internal one.

### 2. `--ignore-scripts` (and `ignore-scripts=true` in `.npmrc`)

Lifecycle scripts are the install-time code-execution surface. Disabling them — on the command line and in `.npmrc` as a backstop — means a dependency cannot run `postinstall` code in CI. Projects that truly need a native build should run that build as an explicit, reviewed step, not as an opaque dependency script.

### 3. Pin the internal scope

```ini
@turla-lab:registry=https://npm.internal.turla-lab.example/
registry=https://registry.npmjs.org/
ignore-scripts=true
```

Pinning `@turla-lab` to the internal registry means every `@turla-lab/*` package can *only* come from there. A public package of the same name is never consulted, which closes dependency confusion at the source — independent of version numbers.

### 4. Fetch-then-verify instead of pipe-to-shell

```yaml
- name: Bootstrap toolchain
  env:
    SETUP_SHA256: 2c26b46b…e7ae
  run: |
    curl -fsSL https://install.example.test/setup.sh -o setup.sh
    echo "${SETUP_SHA256}  setup.sh" | sha256sum --check
    sh ./setup.sh
```

Downloading to a file, checking a pinned digest, and only then running means a tampered or swapped script fails the checksum and the job aborts. The network can no longer hand the runner arbitrary code.

## General rule

Treat the install phase as executing untrusted code. Install locked versions with scripts off, pin every internal scope to its registry, keep a committed lockfile, and never run bytes straight off the network without verifying them.

## Standards

- OWASP CICD-SEC-3 (Dependency Chain Abuse)
- GitHub: *Security hardening for GitHub Actions*
- npm: `npm ci`, scoped-package registries, `ignore-scripts`
