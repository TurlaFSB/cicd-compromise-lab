#!/usr/bin/env bash
# Benign stand-in for an artifact tamper, used by simulate.sh.
#
# Represents an attacker who can write the build artifact between the build
# job's upload and the publish job's download. In a real attack this would
# inject a malicious postinstall script or a backdoored bundle; here it only
# appends a visible marker line so the change is obvious and harmless.
#
# Usage: tamper.sh <path-to-artifact-file>

set -euo pipefail
target="${1:?usage: tamper.sh <artifact-file>}"
[ -f "$target" ] || { echo "no such file: $target" >&2; exit 1; }

printf '\n// INJECTED BY ATTACKER between build and publish (lab PoC)\n' >> "$target"
echo "tampered: $target"
