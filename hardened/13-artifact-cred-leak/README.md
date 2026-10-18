# Hardened workflow — Scenario 13: credential leakage via artifacts

## Before / after

| Aspect | Vulnerable | Hardened |
|---|---|---|
| Checkout credentials | persisted into `.git/config` (default) | `persist-credentials: false` |
| npm token | written to `.npmrc` on disk | passed via `NODE_AUTH_TOKEN` env at publish |
| Upload path | `.` (whole tree) | `dist/` (build output only) |
| Hidden files | `include-hidden-files: true` | default (false) |

## Why each change works

### 1. Don't persist the checkout token

```yaml
- uses: actions/checkout@… # v4.4.0
  with:
    persist-credentials: false
```

Without this, checkout stores the job token in `.git/config`. Setting it to `false` means the token is used for the clone and then discarded — nothing in the working tree carries it, so nothing that archives the tree can leak it.

### 2. Keep the secret off disk

```yaml
- uses: actions/setup-node@… # v4.1.0
  with:
    node-version: "20"
    registry-url: "https://registry.npmjs.org"
- name: Publish
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
  run: npm publish
```

`registry-url` makes setup-node write an `.npmrc` that reads the token from the `NODE_AUTH_TOKEN` environment variable *at publish time* — the file contains the variable reference, not the secret. The literal token exists only as an environment variable for the one step that needs it, and environment variables are not part of the uploaded artifact.

### 3. Upload only what you mean to

```yaml
- uses: actions/upload-artifact@… # v4.6.2
  with:
    name: build-output
    path: dist/
```

A specific directory cannot sweep up `.git/config`, `.npmrc`, or `.env`. This is the single most effective change: even if a secret did land on disk, a scoped path would not ship it.

### 4. Leave hidden files excluded

`upload-artifact` excludes hidden files by default precisely because dotfiles are where credentials hide. The hardened workflow simply does not set `include-hidden-files`, so the safe default stands.

## General rule

Treat an artifact as public to everyone who can read the repo. Upload only build output, keep secrets in environment variables scoped to the step that needs them, and never let the checkout token or a written credential sit in a path that gets archived.

## Standards

- OWASP CICD-SEC-6 (Insufficient Credential Hygiene)
- GitHub: *Security hardening for GitHub Actions* — "Using secrets" and artifact guidance
- `actions/checkout` `persist-credentials`; `actions/upload-artifact` hidden-files behavior
