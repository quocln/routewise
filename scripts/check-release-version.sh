#!/bin/bash
# Fails unless a release tag agrees with every place the version is written, and the
# changelog has a section for it. Usage: scripts/check-release-version.sh v1.0.0
set -euo pipefail

tag="${1:?usage: check-release-version.sh <tag>}"
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "$tag is not a version tag such as v1.0.0" >&2
    exit 1
fi
version="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"

status=0
check() {
    if [ "$2" != "$version" ]; then
        echo "$1 says ${2:-nothing}, the tag says $version" >&2
        status=1
    fi
}
json_version() { sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$1" | head -n 1; }

check desktop/package.json "$(json_version "$root/desktop/package.json")"
check desktop/src-tauri/tauri.conf.json "$(json_version "$root/desktop/src-tauri/tauri.conf.json")"
check desktop/src-tauri/Cargo.toml "$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$root/desktop/src-tauri/Cargo.toml" | head -n 1)"

if ! grep -q "^## \[$version\] - [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" "$root/CHANGELOG.md"; then
    echo "CHANGELOG.md has no dated section for $version" >&2
    status=1
fi
exit "$status"
