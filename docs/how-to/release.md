# Release

Pushing a version tag runs [`release.yml`](../../.github/workflows/release.yml). It checks the tag, runs everything CI runs, builds every platform, and leaves a **draft** release. Nothing is public until you publish it.

## Steps

1. On `main`, write the version in all three places:
   - `desktop/package.json`
   - `desktop/src-tauri/tauri.conf.json`
   - `desktop/src-tauri/Cargo.toml`, then run `cargo check` so `Cargo.lock` follows
2. In `CHANGELOG.md`, add a section for the version and date, above the last one:

   ```markdown
   ## [1.1.0] - 2026-12-01
   ```

3. Check it, commit, tag and push:

   ```bash
   bash scripts/check-release-version.sh v1.1.0
   git commit -am "chore: release 1.1.0"
   git tag v1.1.0
   git push origin main v1.1.0
   ```

4. When the workflow finishes, open the draft under **Releases**, try the downloads, and publish.

A tag with a suffix, such as `v1.1.0-rc.1`, becomes a pre-release.

## What it builds

| Platform | File |
|---|---|
| macOS, universal | `RouteWise-<version>-macos-universal.zip` |
| Windows, x64 and arm64 | NSIS installers |
| Linux, x64 | `.deb` and AppImage |

Plus `SHA256SUMS`, covering all of them.

## If it fails

- **Check the tag** fails: a version or the changelog disagrees with the tag, or the tag is not on `main`. Delete the tag, fix it, and tag again: `git push origin :refs/tags/v1.1.0`.
- **A build** fails: re-run the failed jobs if it was a flaky runner. Otherwise fix it and tag a new patch version.

## What you still need to do

- **macOS signing.** The app is signed ad hoc, not notarized, because that needs an Apple Developer account. Gatekeeper blocks a downloaded copy until the user chooses **Open Anyway** in **System Settings > Privacy & Security**.
- **Windows signing.** The installer is unsigned, so SmartScreen warns.
- **Update checks** read this repository's public releases, so they find nothing while it is private.
