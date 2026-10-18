# Detection — Scenario 12: OIDC trust policy misconfiguration

## Sigma rule

[`oidc-trust-policy.yml`](oidc-trust-policy.yml) fires on a workflow definition that grants `id-token: write` at workflow level or reachable from an untrusted trigger. (The cloud-side trust policy is not a GitHub log, so the Sigma rule covers the GitHub half; the scanner covers both.)

## Scanner

[`detect.sh`](detect.sh) checks **both** sides of the OIDC exchange. Trust-policy JSON is parsed by [`policy.py`](policy.py).

| Vector | Side | What it catches |
|---|---|---|
| WILDCARD SUBJECT | cloud | a `sub` condition admitting more than one repo or any ref (`repo:org/*`, trailing `:*`, bare `*`) |
| NO SUBJECT CONDITION | cloud | the GitHub OIDC provider federated with no `sub` condition — any repo on GitHub qualifies |
| MISSING AUDIENCE CONDITION | cloud | no `aud` condition constraining the token audience |
| WORKFLOW-LEVEL ID-TOKEN | GitHub | `id-token: write` at workflow level, so every job can mint a token |
| ID-TOKEN ON UNTRUSTED TRIGGER | GitHub | `id-token: write` reachable from `pull_request_target`, `workflow_run`, `issue_comment`, ... |

### Usage

```bash
./detect.sh static  /path/to/repo             # scan workflows + nearby trust policies
./detect.sh static  path/to/trust-policy.json # scan a single policy anywhere
./detect.sh runtime owner/repo                # workflows only, via the GitHub API (needs gh)
```

Exit codes: `0` clean, `1` findings, `2` usage/dependency error. Requires `python3` for the trust-policy half.

## Trust-policy discovery

In repo-scan mode the scanner looks for IAM trust policies (`*.json` containing `token.actions.githubusercontent.com` and `sts:AssumeRoleWithWebIdentity`) **up to two directory levels deep** — the repo root, `.github/`, and top-level infra directories. This keeps a whole-repo scan from sweeping unrelated JSON. If your trust policy lives deeper (e.g. `infra/aws/iam/role.json`), point the scanner at the file directly.

## False positives

| Source | Why it may be benign |
|---|---|
| `id-token: write` on one job, trusted trigger, with a trust policy that pins `sub` + `aud` | The intended pattern — not flagged |
| A `StringLike` `sub` whose only wildcard is inside a fully-qualified ref path | Flagged conservatively: any `*` widens the trust boundary; review it |
| A role trust policy for a non-GitHub federated IdP | Not matched — `policy.py` only reports GitHub Actions provider statements |

## Limitations

- **Two halves, scanned separately.** The scanner does not correlate a specific workflow with a specific role ARN; it reports each misconfiguration independently.
- **AWS-shaped.** `policy.py` understands AWS IAM trust-policy JSON. GCP Workload Identity Federation and Azure federated credentials use different shapes and are not parsed (the workflow-side vectors still apply).
- **Discovery depth.** Trust policies deeper than two levels are only scanned when passed directly (see above).
- **`*` is treated as broad.** Any wildcard in a `sub` value is flagged; a deployment that deliberately scopes to `…/environment:*` under other strong conditions would need manual review.
