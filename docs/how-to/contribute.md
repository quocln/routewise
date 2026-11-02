# Contribute

## Layout

```
cmd/routewise/     The one binary: CLI and helper daemon
internal/          Go packages: daemon, route, monitor, dns, tunnels, API
desktop/           The app: a Next.js UI in src/, and its Rust shell in src-tauri/
scripts/           Install, uninstall, and packaging helpers
config/            Starter configuration
docs/              This documentation
```

The layout follows [Go's module guide](https://go.dev/doc/modules/layout). Why `desktop/`:
[decision 0001](../decisions/0001-desktop-app-folder.md). How the pieces fit:
[Architecture](../explanation/architecture.md).

## Build and test

```bash
make build                 # the Go binary
make app                   # the universal macOS app with the helper
go test ./...              # Go
go test -race ./internal/daemon ./internal/route
```

In `desktop/`, with the pnpm version it pins (`npx pnpm@<version>` works):

```bash
pnpm test                  # Vitest
pnpm exec tsc --noEmit
pnpm gen:types             # regenerate TypeScript from the Go API types
pnpm check:types           # CI fails if they are out of date
```

In `desktop/src-tauri/`:

```bash
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

CI runs these on macOS, Linux and Windows. On Windows, run the Go tests from an elevated shell:
they create files only Administrators can change and talk to a pipe server the client trusts
only when elevated. [Release](release.md) covers shipping.

## Proof of completion

Unit tests cannot build a root-owned helper, a real `utun`, or the kernel's routing table. **A change to routing, DNS or the helper
is not done until it has been exercised against an installed helper**, with `sudo make install`.

Fakes hide real bugs. `internal/daemon/kernel_route_table_fake_test.go` models the kernel's rules, and a test double should
share the awkward properties of what it replaces.

## Where to extend

| To add | Do this |
|---|---|
| A setting | A field in `config.Config`, a row in `config.Settings` (a test fails without it). If the app can change it, fields in `api.SetSettingsParams` and `api.Settings` and a row in `settingRules` |
| An RPC method | A constant and a row with its auth level in `rpcMethods` |
| A built-in VPN kind | One type and one entry in `tunnelKinds` |
| A routing rule | `planRoutes` decides who gets a route and has no side effects |
| A role with routes of its own | A component like `defaultVPNController`, taking a narrow host interface, reconciled before each sync |
| Something that must survive a crash | A `ledger.Ledger[T]` and a recovery step at start |
| A check that keeps something in place | A due time in `controlLoop`, not a new goroutine |
| A figure the window shows | A push from the Rust shell, not a timer in the window |

## Conventions

- `gofmt`, and tests named for the behavior they prove.
- Comments say why, in plain words. No plan IDs, phase numbers or audit labels in code or test names.
- Conventional commit messages.
- Secrets never reach logs, RPC replies or exports.
- A change to behavior updates its doc page. A consequential choice gets a [decision record](../decisions/README.md).
- `CLAUDE.md` holds the rules agents follow, so keep it short and true.
