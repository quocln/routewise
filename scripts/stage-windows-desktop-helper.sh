#!/usr/bin/env bash
# Stages the Windows helper for the Tauri bundle: builds routewise.exe and puts
# the matching wintun.dll beside it in desktop/src-tauri/resources/helper,
# where the bundle picks both up (the helper installs itself from there).
#
# Usage: scripts/stage-windows-desktop-helper.sh <amd64|arm64>
#
# Runs on any host with Go and curl, including Git Bash on a Windows machine.
# VERSION and COMMIT stamp the binary; both default to values that mark an
# unstamped local build.
set -euo pipefail

arch="${1:-}"
if [[ "$arch" != "amd64" && "$arch" != "arm64" ]]; then
  echo "usage: $0 <amd64|arm64>" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$root/desktop/src-tauri/resources/helper"

version="${VERSION:-$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$root/desktop/package.json" | head -n 1)}"
commit="${COMMIT:-$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
built="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# A stale helper of another architecture must never ride along in the bundle.
rm -rf "$dest"
mkdir -p "$dest"

(
  cd "$root"
  GOOS=windows GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-X main.Version=$version -X main.Commit=$commit -X main.BuildTime=$built" \
    -o "$dest/routewise.exe" ./cmd/routewise
)

bash "$root/scripts/fetch-wintun.sh" "$arch" "$dest"
echo "staged the windows/$arch helper in $dest"
