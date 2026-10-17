#!/usr/bin/env bash
# Benign stand-in for a runner-persistence implant, used by simulate.sh.
#
# Represents what untrusted PR code drops on a self-hosted runner so it
# outlives the job. A real implant would install a cron job, a user systemd
# unit, a shell-profile hook, or a background listener that waits for a
# privileged job and exfiltrates its secrets. This lab version only writes a
# marker file into a "persistent" directory and prints what it did.
#
# Usage: persist.sh <persistent-dir>

set -euo pipefail
persist_dir="${1:?usage: persist.sh <persistent-dir>}"
mkdir -p "$persist_dir"

marker="$persist_dir/.lab-implant"
cat > "$marker" <<'EOF'
RUNNER PERSISTENCE PROOF-OF-CONCEPT
Dropped by untrusted PR code during a job on a self-hosted runner.
On a reused (non-ephemeral) runner this file is still here when the next
job starts. A real implant would now wait for a privileged job and steal
its GITHUB_TOKEN / secrets, or tamper its build output.
EOF

echo "[persist] wrote implant to $marker (survives on a reused runner)"
