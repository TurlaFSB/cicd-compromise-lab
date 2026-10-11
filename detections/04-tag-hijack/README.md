# Detection — Scenario 04: Mutable action tag hijack

## Sigma rule

[`tag-hijack.yml`](tag-hijack.yml) fires when a workflow definition contains a `uses:` reference that is not pinned to a full 40-character commit SHA. Five detection conditions cover the full range of mutable references:

| Condition | Pattern | Example |
|---|---|---|
| `mutable_version_tag` | `@v` followed by a digit | `actions/checkout@v4` |
| `mutable_branch_ref` | `@main`, `@master`, `@develop`, `@dev`, `@trunk` | `org/action@main` |
| `mutable_special_tag` | `@latest`, `@stable`, `@release`, `@nightly` | `org/action@latest` |
| `no_ref` | No `@` at all — implicit default branch | `org/action` |
| `short_sha` | Hex string shorter than 40 characters | `org/action@abc1234` |

Exclusions: local actions (`./path`), Docker references (`docker://`), and comment lines are filtered out.

## Scanner

[`detect.sh`](detect.sh) implements the Sigma rule as an executable scanner with two modes:

### Static mode

Scans local workflow files for mutable action references:

```bash
# Scan a local repo
./detect.sh static /path/to/repo

# Skip official GitHub actions (actions/*, github/*)
./detect.sh static /path/to/repo --skip-official
```

### Runtime mode

Fetches workflow files from a GitHub repository via the API:

```bash
# Scan a remote repo
./detect.sh runtime owner/repo

# Skip official GitHub actions
./detect.sh runtime owner/repo --skip-official
```

Requires the `gh` CLI, authenticated with access to the target repository.

### Output format

Each finding is printed as:

```
FINDING: <filename>:<line>: <VECTOR> — '<uses_value>' <description>.
  Fix: pin to the commit SHA behind <ref> and note the tag in a comment.
```

Exit codes:
- `0` — all actions pinned by full commit SHA
- `1` — mutable action tag references detected
- `2` — usage error or missing dependency

### `--skip-official` flag

By default, the scanner flags all mutable references, including GitHub's own `actions/*` and `github/*` actions. While these are maintained by GitHub and carry lower (but non-zero) risk, some organizations accept the trade-off for readability.

Pass `--skip-official` to suppress findings for `actions/*` and `github/*`. The hardened workflow in this lab pins everything — official or not — because defense in depth means treating even trusted dependencies as potentially mutable.

## Scan your own repos

```bash
# Scan all repos in your org
for repo in $(gh repo list your-org --limit 100 --json nameWithOwner -q '.[].nameWithOwner'); do
  ./detect.sh runtime "$repo"
done

# Static scan of a local checkout
./detect.sh static ~/projects/your-app
```

## False positives

| Source | Mitigation |
|---|---|
| Official GitHub actions (`actions/*`, `github/*`) | Use `--skip-official` if your policy accepts the risk |
| Archived or template repos not used in production | Exclude from scan scope |
| Actions in the same org (org-internal actions) | These are technically first-party, but the scanner flags them because org accounts can also be compromised. Consider `--skip-official` extended to your own org. |

## Limitations

- **No runtime log analysis**: unlike scenarios 01–03, the tag-hijack attack leaves no distinctive pattern in workflow run logs. The detection is purely structural (does the YAML pin by SHA?).
- **Tag-to-SHA verification**: the scanner checks whether the ref looks like a SHA but does not verify that the SHA is valid or corresponds to a known upstream release. A fabricated 40-char hex string passes the check.
- **Composite action depth**: the scanner checks the top-level workflow but does not recurse into composite actions' own `uses:` references. A pinned action that internally uses mutable tags is not caught.
