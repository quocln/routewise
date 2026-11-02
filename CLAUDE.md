# RouteWise

Sends chosen domains through a VPN and everything else direct, by editing the kernel routing table. A Go helper runs as root; a Tauri app and a CLI talk to it over JSON-RPC.

Docs map: `docs/README.md`. How the parts fit: `docs/explanation/architecture.md`.

## Layout

- `cmd/routewise/`: the one Go binary, both CLI and helper daemon.
- `internal/`: Go packages. `daemon` orchestrates, `route` edits the table, `monitor` detects VPNs, `api` is the RPC.
- `desktop/`: the app. `src/` is the Next.js UI, `src-tauri/` the Rust shell.
- `scripts/`, `config/`: install, packaging, starter config.

## Commands

```bash
go test ./...                                    # Go
go test -race ./internal/daemon ./internal/route
GOOS=linux go vet ./... && GOOS=windows go vet ./...

cd desktop
npx pnpm@$(node -p "require('./package.json').packageManager.split('@')[1]") <command>
# commands: test, typecheck, lint, gen:types, check:types

cd desktop/src-tauri
cargo test --lib && cargo clippy --all-targets -- -D warnings

make app                                         # universal macOS build
sudo make install                                # needs a real terminal for the password
```

After changing `internal/api` types, run `gen:types`. CI fails on stale generated types.

## Rules

- **A change to routing, DNS or the helper is not done until exercised against an installed helper.** Unit tests cannot build a root-owned helper, a real `utun`, or the kernel table. Say plainly what was not exercised, and update `docs/reference/platforms.md` when something is proven.
- Installing restarts the helper, which disconnects built-in VPNs.
- A test double must share the awkward properties of what it replaces. A fake tunnel that was a comparable pointer once hid a panic that took the helper down.
- Secrets never reach logs, RPC replies or exports.
- A consequential choice gets a record in `docs/decisions/`. A behavior change updates its doc page and `CHANGELOG.md` in the same change.
- Comments say why. No plan IDs, phase numbers or audit labels in code, test names or commits.
- Conventional commits, with no AI references. Commit or push only when asked.

## Running it

- CLI on macOS: `/Library/PrivilegedHelperTools/com.routewise.helper <command>`, unless symlinked as `routewise`.
- Never run `/Applications/RouteWise.app/Contents/MacOS/routewise-desktop` for CLI work: it starts the GUI.
- launchd has `KeepAlive`, so `routewise stop` is followed by a restart. To stop for good: `sudo launchctl bootout system/com.routewise.helper`.
- RPC requests need `"jsonrpc":"2.0"`.

## Where to add things

See "Where to extend" in `docs/how-to/contribute.md`: settings go in `config.Settings`, RPC methods in `rpcMethods`, VPN kinds in `tunnelKinds`, routing rules in `planRoutes`, periodic checks in `controlLoop`.

## Releases

Pushing a `v*.*.*` tag on `main` builds every platform and drafts a release. Steps: `docs/how-to/release.md`.
