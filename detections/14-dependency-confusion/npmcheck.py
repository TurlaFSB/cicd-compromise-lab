#!/usr/bin/env python3
"""npmcheck.py — detect dependency-confusion exposure from an npm manifest and
its .npmrc, for scenario 14's detect.sh.

A scoped dependency (``@scope/name``) resolves against whatever registry the
scope is mapped to. If the project's .npmrc has no ``@scope:registry=`` line,
that scope falls back to the public registry — where an attacker can publish a
package of the same name at a higher version (dependency confusion).

Usage: npmcheck.py <package.json> [<.npmrc>]

Facts printed (tab-separated), with the package.json line of the dependency:
  UNPINNED_SCOPE  <line>  <scope>  <example-package>

Exit codes: 0 parsed, 2 package.json unreadable/!JSON.
"""
import json
import re
import sys

DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def pinned_scopes(npmrc_path):
    """Scopes with an explicit <scope>:registry= line in .npmrc."""
    scopes = set()
    if not npmrc_path:
        return scopes
    try:
        text = open(npmrc_path, encoding="utf-8").read()
    except OSError:
        return scopes
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or line.startswith(";") or not line:
            continue
        m = re.match(r"^(@[^:=\s]+):registry\s*=", line)
        if m:
            scopes.add(m.group(1).lower())
    return scopes


def line_of(text, needle):
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: npmcheck.py <package.json> [<.npmrc>]", file=sys.stderr)
        return 2
    pkg_path = sys.argv[1]
    npmrc_path = sys.argv[2] if len(sys.argv) == 3 else None

    try:
        text = open(pkg_path, encoding="utf-8").read()
        doc = json.loads(text)
    except (OSError, ValueError):
        return 2
    if not isinstance(doc, dict):
        return 0

    pinned = pinned_scopes(npmrc_path)

    seen_scopes = {}
    for field in DEP_FIELDS:
        deps = doc.get(field)
        if not isinstance(deps, dict):
            continue
        for name in deps:
            if not name.startswith("@") or "/" not in name:
                continue
            scope = name.split("/", 1)[0].lower()
            # Report each scope once, at the first dependency that uses it.
            if scope not in seen_scopes:
                seen_scopes[scope] = (line_of(text, '"%s"' % name), name)

    for scope, (ln, example) in sorted(seen_scopes.items()):
        if scope not in pinned:
            print("UNPINNED_SCOPE\t{}\t{}\t{}".format(ln, scope, example))

    return 0


if __name__ == "__main__":
    sys.exit(main())
