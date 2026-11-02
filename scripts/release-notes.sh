#!/bin/bash
# Prints one version's section of the changelog, without its heading.
# Usage: scripts/release-notes.sh 1.0.0
set -euo pipefail

version="${1:?usage: release-notes.sh <version>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
awk -v heading="## [$version]" '
    index($0, heading) == 1 { found = 1; next }
    found && /^## / { exit }
    found { print }
' "$root/CHANGELOG.md" | sed -e '/./,$!d'
