#!/usr/bin/env python3
"""Convert lab detector findings into SARIF 2.1.0 for GitHub code scanning.

Reads tab-prefixed detector output on stdin, one physical line per record:

    <scenario_id>\t<raw detector line>

Only lines whose raw part begins with "FINDING: " become SARIF results; every
other line (OK/NOTE/headers/detail) is ignored. The scenario_id prefix is
added by the `lab` CLI so this converter knows which detector emitted each
line without re-running anything.

A finding body looks like one of:

    ci.yml: VULNERABLE — pull_request_target + PR head checkout ...
    deploy.yml: BROAD PERMISSIONS — write permissions ...
    ci.yml:36: MUTABLE TAG — 'actions/checkout@v4' pinned by version tag ...
    triage.yml: untrusted context interpolated directly in run: step ...

so the parser pulls an optional line number and an optional uppercase VECTOR
(the text before an em dash) to build a stable rule id.

Usage:
    lab-detectors | to_sarif.py [--tool-version X.Y.Z] > out.sarif
"""

import argparse
import json
import re
import sys

TOOL_NAME = "cicd-compromise-lab"
INFO_URI = "https://github.com/TurlaFSB/cicd-compromise-lab"

# Per-scenario OWASP help links and human titles.
SCENARIOS = {
    "01-pwn-request": (
        "Poisoned pipeline execution (pwn request)",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    "02-script-injection": (
        "Script injection via untrusted context",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    "03-secret-exfil": (
        "Insufficient credential hygiene / secret exfiltration",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
    ),
    "04-tag-hijack": (
        "Dependency chain abuse via mutable action tags",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
    ),
    "05-cache-poisoning": (
        "Improper artifact integrity validation / cache poisoning",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
    ),
    "06-artifact-tampering": (
        "Artifact integrity not bound to build provenance",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
    ),
    "07-runner-persistence": (
        "Untrusted code on a reusable self-hosted runner",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration",
    ),
    "08-env-injection": (
        "GITHUB_ENV / GITHUB_PATH injection",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    "09-reusable-workflow": (
        "Reusable workflow trust boundary",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
    ),
    "10-token-overprivilege": (
        "GITHUB_TOKEN over-privilege",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC",
    ),
    "11-workflow-run-poisoning": (
        "workflow_run artifact poisoning",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    "12-oidc-trust-policy": (
        "OIDC trust policy misconfiguration",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC",
    ),
    "13-artifact-cred-leak": (
        "Credential leakage via artifacts",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
    ),
    "14-dependency-confusion": (
        "Dependency confusion / install-script abuse",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
    ),
}

# Matches "<file>" or "<file>:<line>" then ": <message>".
BODY_RE = re.compile(r"^(?P<file>[\w.\-/]+?)(?::(?P<line>\d+))?: (?P<msg>.*)$")
# A leading uppercase VECTOR phrase before an em dash, e.g. "MUTABLE TAG — ...".
# Underscores are allowed so phrases naming workflow tokens (GITHUB_ENV,
# WORKFLOW_RUN) stay a single vector rather than falling back to the scenario.
VECTOR_RE = re.compile(r"^(?P<vector>[A-Z][A-Z0-9 /_\-]+?) — ")


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def parse(stream):
    """Yield (scenario_id, rule_id, vector_title, uri, line, message)."""
    for raw in stream:
        raw = raw.rstrip("\n")
        if "\t" not in raw:
            continue
        sid, line = raw.split("\t", 1)
        if not line.startswith("FINDING: "):
            continue
        body = line[len("FINDING: "):]

        # Runtime-mode lines may prefix "workflow " / "run N: workflow "; the
        # lab CLI only drives static mode, but stay lenient if they appear.
        body = re.sub(r"^(run \S+: )?workflow ", "", body)

        m = BODY_RE.match(body)
        if not m:
            # Could not localize to a file; attach to the scenario at large.
            yield sid, sid, None, None, None, body
            continue

        fname = m.group("file")
        lineno = int(m.group("line")) if m.group("line") else None
        msg = m.group("msg")

        vm = VECTOR_RE.match(msg)
        if vm:
            vector = vm.group("vector").strip()
            rule_id = "{}/{}".format(sid, slugify(vector))
            vector_title = vector.title()
        else:
            vector = None
            rule_id = sid
            vector_title = None

        # Most detectors print a workflow basename; GitHub maps SARIF to source
        # by repo-relative path, and lab workflows live under .github/workflows.
        # A finding that already carries a path (contains "/") or names a
        # non-workflow file (e.g. an OIDC trust policy *.json) is used as-is.
        if "/" in fname or not fname.endswith((".yml", ".yaml")):
            uri = fname
        else:
            uri = ".github/workflows/{}".format(fname)
        yield sid, rule_id, vector_title, uri, lineno, msg


def build(records, tool_version):
    rules = {}
    rule_order = []
    results = []

    for sid, rule_id, vector_title, uri, lineno, msg in records:
        scen_title, help_uri = SCENARIOS.get(
            sid, (sid, INFO_URI)
        )
        if rule_id not in rules:
            name = vector_title or scen_title
            rules[rule_id] = {
                "id": rule_id,
                "name": "".join(p.capitalize() for p in re.split(r"[^A-Za-z0-9]+", rule_id) if p),
                "shortDescription": {"text": name},
                "fullDescription": {"text": scen_title},
                "helpUri": help_uri,
                "help": {"text": "See {}".format(help_uri)},
                "defaultConfiguration": {"level": "error"},
            }
            rule_order.append(rule_id)

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri}
                if uri
                else {"uri": "unknown"},
            }
        }
        if lineno:
            location["physicalLocation"]["region"] = {"startLine": lineno}

        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": msg},
                "locations": [location],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFO_URI,
                        "version": tool_version,
                        "rules": [rules[r] for r in rule_order],
                    }
                },
                "results": results,
            }
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="Convert lab findings to SARIF 2.1.0")
    ap.add_argument("--tool-version", default="0.0.0")
    args = ap.parse_args()

    records = list(parse(sys.stdin))
    sarif = build(records, args.tool_version)
    json.dump(sarif, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
