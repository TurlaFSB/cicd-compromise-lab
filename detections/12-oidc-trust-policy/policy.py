#!/usr/bin/env python3
"""policy.py — parse an AWS IAM role trust policy and report GitHub Actions
OIDC misconfigurations as tab-separated facts for detect.sh.

A trust policy is "in scope" when a statement allows
sts:AssumeRoleWithWebIdentity federated to the GitHub Actions OIDC provider
(token.actions.githubusercontent.com). For each such statement we check:

  * the subject condition (<provider>:sub) — is it absent, "*", or a wildcard
    that admits any repository or any ref?
  * the audience condition (<provider>:aud) — is it present at all?

Facts printed (one per line, tab-separated):
  TRUST_POLICY  <n_statements_in_scope>
  WILDCARD_SUB  <line>  <value>
  NO_SUB        <line>
  NO_AUD        <line>

Nothing is printed for a file that is not a GitHub Actions trust policy.
Exit codes: 0 parsed (in scope or not), 2 unreadable/!JSON.
"""
import json
import sys

PROVIDER = "token.actions.githubusercontent.com"
WEBIDENTITY = "sts:assumerolewithwebidentity"


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def line_of(text, needle):
    """1-based line number of the first occurrence of needle, or 1."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def federates_github(stmt):
    principal = stmt.get("Principal", {})
    fed = []
    if isinstance(principal, dict):
        fed = as_list(principal.get("Federated"))
    actions = [a.lower() for a in as_list(stmt.get("Action"))]
    if WEBIDENTITY not in actions:
        return False
    return any(PROVIDER in str(f) for f in fed)


def collect_conditions(cond, suffix):
    """All values across all operators whose key is <PROVIDER>:<suffix>."""
    key = "{}:{}".format(PROVIDER, suffix)
    out = []
    if not isinstance(cond, dict):
        return out
    for _op, mapping in cond.items():
        if not isinstance(mapping, dict):
            continue
        for k, v in mapping.items():
            if k.lower() == key.lower():
                out.extend(as_list(v))
    return out


def sub_is_broad(value):
    """True if a subject claim admits more than one repo or any ref."""
    v = str(value)
    if v == "*":
        return True
    # repo:org/*  or  repo:org/repo:*  or any trailing wildcard on the ref,
    # or a wildcard anywhere before the repo is fully qualified.
    if "*" in v:
        # A wildcard that is only inside a fully-qualified ref segment after a
        # concrete repo (e.g. repo:o/r:ref:refs/heads/feature/*) is narrower,
        # but still ref-broad; treat any '*' as broad for a trust boundary.
        return True
    return False


def main():
    if len(sys.argv) != 2:
        print("usage: policy.py <trust-policy.json>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        return 2
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        # Not JSON (or not parseable) — silently not a policy.
        return 0

    statements = as_list(doc.get("Statement")) if isinstance(doc, dict) else []
    in_scope = [s for s in statements if isinstance(s, dict) and federates_github(s)]
    if not in_scope:
        return 0

    print("TRUST_POLICY\t{}".format(len(in_scope)))

    for stmt in in_scope:
        cond = stmt.get("Condition", {})
        subs = collect_conditions(cond, "sub")
        auds = collect_conditions(cond, "aud")

        if not subs:
            ln = line_of(text, '"Condition"')
            print("NO_SUB\t{}".format(ln))
        else:
            for value in subs:
                if sub_is_broad(value):
                    ln = line_of(text, str(value))
                    print("WILDCARD_SUB\t{}\t{}".format(ln, value))

        if not auds:
            ln = line_of(text, '"Condition"')
            print("NO_AUD\t{}".format(ln))

    return 0


if __name__ == "__main__":
    sys.exit(main())
