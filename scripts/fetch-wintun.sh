#!/usr/bin/env bash
# Fetches the official Wintun driver library for the Windows helper and copies
# wintun.dll for one architecture to a destination directory, where it must sit
# beside routewise.exe (the helper creates its tunnels through it).
#
# Usage: scripts/fetch-wintun.sh <amd64|arm64> <destination-dir>
#
# The zip is pinned by version and SHA-256; a mismatch aborts without writing
# anything to the destination. With WINTUN_CACHE_DIR set, a zip kept there is
# used instead of downloading, and a freshly verified download is kept there;
# a cached zip that fails the checksum is discarded and downloaded again.
set -euo pipefail

VERSION="0.14.1"
SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
URL="https://www.wintun.net/builds/wintun-${VERSION}.zip"

arch="${1:-}"
dest="${2:-}"
if [[ "$arch" != "amd64" && "$arch" != "arm64" ]] || [[ -z "$dest" ]]; then
  echo "usage: $0 <amd64|arm64> <destination-dir>" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

cache="${WINTUN_CACHE_DIR:-}"
cached="${cache:+$cache/wintun-${VERSION}.zip}"
if [[ -n "$cached" && -f "$cached" ]]; then
  cp "$cached" "$work/wintun.zip"
  if [[ "$(sha256_of "$work/wintun.zip")" != "$SHA256" ]]; then
    echo "discarding the cached wintun-${VERSION}.zip: checksum mismatch" >&2
    rm -f "$cached" "$work/wintun.zip"
  fi
fi

if [[ ! -f "$work/wintun.zip" ]]; then
  curl -fsSL --retry 3 -o "$work/wintun.zip" "$URL"
  actual="$(sha256_of "$work/wintun.zip")"
  if [[ "$actual" != "$SHA256" ]]; then
    echo "wintun-${VERSION}.zip checksum mismatch: got $actual, want $SHA256" >&2
    exit 1
  fi
  if [[ -n "$cached" ]]; then
    mkdir -p "$cache"
    cp "$work/wintun.zip" "$cached"
  fi
fi

# Extract into its own empty directory; the archive is untrusted until verified
# and only the one file is taken from it.
mkdir "$work/extract"
member="wintun/bin/${arch}/wintun.dll"
if command -v unzip >/dev/null 2>&1; then
  unzip -q -j "$work/wintun.zip" "$member" -d "$work/extract"
elif command -v 7z >/dev/null 2>&1; then
  # Git Bash on Windows has no unzip but the runners ship 7-Zip, a native
  # program that needs Windows paths.
  native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
  7z e -y -bd "-o$(native "$work/extract")" "$(native "$work/wintun.zip")" "$member" >/dev/null
else
  echo "neither unzip nor 7z is available to unpack the archive" >&2
  exit 1
fi
if [[ ! -f "$work/extract/wintun.dll" ]]; then
  echo "wintun.dll was not found in the archive at $member" >&2
  exit 1
fi

mkdir -p "$dest"
cp "$work/extract/wintun.dll" "$dest/wintun.dll"
echo "wintun ${VERSION} (${arch}) -> ${dest}/wintun.dll"
