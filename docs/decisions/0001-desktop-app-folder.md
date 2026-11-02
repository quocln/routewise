# 0001 Desktop App Folder

Date: 2026-11-02

## Status

Accepted

## Context

The Tauri app lived in `desktop-app/`. The name repeats itself beside `cmd/` and
`internal/`, and the repository is expected to grow more than one kind of front end.

Go's module layout guide puts commands in `cmd/` and server logic in `internal/`, and
leaves "the project's other directories with non-Go code" beside them with no required
name. Tauri requires only that `src-tauri/` holds `tauri.conf.json`. So the name is
ours to choose.

Comparable projects (2026-11-02):

| Project | Desktop app | What `client/` means there |
|---|---|---|
| Mullvad VPN | `desktop/`, beside `android/` and `ios/` | none |
| Firezone | `rust/gui-client/`, with `src-tauri/` and `src-frontend/` | a kind of VPN client |
| Ollama | `app/`, in a Go module with `cmd/` and `internal/` | none |
| Syncthing | `gui/` (a web UI) | none |
| Spacedrive | `apps/tauri/`, among several apps | none |
| NetBird | `client/ui/` | the whole agent: daemon, CLI, UI, mobile |
| Tailscale | none in this repository | Go client libraries |
| Pritunl Client | `client/`, beside `service/` and `cli/` | the Electron app |

## Decision

The app lives in `desktop/`. Its Rust shell stays in `desktop/src-tauri/`, Tauri's
default. A mobile app would sit beside it as `android/` or `ios/`.

## Alternatives Considered

1. `client/`. In this repository "client" already means a VPN client (`vpnclient`, the
   allowlist, the UI's "VPN apps") and the CLI's connection to the helper (`api.Client`).
   The CLI is a client of the helper too, so the name would not say which one. Among
   the projects above it means three different things.
2. `apps/desktop/`. It suits a repository with several apps sharing packages, as
   Spacedrive has. With one app it adds a level for nothing, and moving later is cheap.
3. `app/` or `ui/`. `app` is reasonable, but says nothing about platform once a mobile
   app exists. `ui` undersells a folder that also holds a Rust shell.
4. Moving Go into `server/` or `backend/`. `go.mod`, `cmd/` and `internal/` at the root
   is what the Go guide shows, and moving them would change every import path.

## Consequences

Paths in the Makefile, CI, scripts and docs say `desktop/`. The bundle identifier, `com.routewise.desktop`, and
the installed `RouteWise.app` are unchanged, so nothing moves on a user's machine.
