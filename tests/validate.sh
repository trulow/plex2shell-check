#!/usr/bin/env bash
set -eu
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/plex-check.sh"
# Check that public APIs, exit codes, and the response parser remain present.
grep -q 'parse_identity()' "$root/plex-check.sh"
grep -q 'container_network()' "$root/plex-check.sh"
grep -q 'check_latest_release()' "$root/plex-check.sh"
grep -q 'FIX_MIN=' "$root/plex-check.sh"
echo 'Syntax and structural checks passed.'
