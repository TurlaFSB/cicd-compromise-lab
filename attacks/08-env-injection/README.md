# Scenario 08 — GITHUB_ENV / GITHUB_PATH injection

**OWASP:** CICD-SEC-4 (Poisoned Pipeline Execution) · **MITRE ATT&CK:** T1574 (Hijack Execution Flow)

## Target

An `issues`-triggered workflow that writes the untrusted issue title into `$GITHUB_ENV` and the untrusted body into `$GITHUB_PATH`.

## The vulnerability

GitHub Actions exposes two files that a step can append to:

- **`$GITHUB_ENV`** — each `KEY=VALUE` line becomes an environment variable in every later step of the job.
- **`$GITHUB_PATH`** — each line is prepended to `PATH` for every later step.

When a workflow echoes attacker-controlled text into either file, the attacker controls part of the runner's environment:

```bash
echo "ISSUE_TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
echo "${{ github.event.issue.body }}" >> "$GITHUB_PATH"
```

- A title containing a newline followed by `NODE_OPTIONS=--require /tmp/evil.js` injects a **second** environment variable. The next `node` invocation loads the attacker's module — arbitrary code execution.
- A body naming an attacker-writable directory is prepended to `PATH`, so a planted `node`/`npm`/`python` shim runs instead of the real tool.

The template expansion happens before the shell runs, so the untrusted value is placed into the `GITHUB_ENV` line literally — exactly the injection surface.

## Simulation

```bash
./simulate.sh                                   # vulnerable triage.yml: INJECTABLE (exit 1)
./simulate.sh ../../hardened/08-env-injection/triage.yml   # hardened: SAFE (exit 0)
```

Part 1 takes the attacker "issue title" from `payload/inject.txt` (a benign first line plus an injected `NODE_OPTIONS` line), appends it to a fake `GITHUB_ENV` the vulnerable way, and parses the result — showing `NODE_OPTIONS` is now a set variable the author never wrote. The safe handling keeps the value in a shell variable and writes nothing untrusted, so no extra variable appears. Part 2 inspects the workflow for untrusted writes to the env files.

## Payload

`payload/inject.txt` is the crafted issue title: a plausible first line and a second line that smuggles `NODE_OPTIONS`. Benign in the lab (the referenced module does not exist); it only demonstrates that the variable is injected.

## Fix direction

See `hardened/08-env-injection/`. Summary:

1. **Pass untrusted data through step-scoped `env:`** — the runner sets it literally, so a newline is just data and cannot define a new variable (the same lesson as scenario 02).
2. **Never write untrusted data to `$GITHUB_PATH`.**
3. **If a value must cross steps**, sanitize it, write it under a **fixed** name using a **random heredoc delimiter** so the value can neither rename the variable nor close the block.
4. Double-quote all variable references.
