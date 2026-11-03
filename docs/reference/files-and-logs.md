# Files and logs

## Locations

| What | macOS | Linux | Windows |
|---|---|---|---|
| Database | `/Library/Application Support/RouteWise/routewise.db` | `/var/lib/routewise/` | `%ProgramData%\RouteWise\` |
| Helper binary | `/Library/PrivilegedHelperTools/com.routewise.helper` | `routewise` on the service's path | `%ProgramFiles%\RouteWise\routewise.exe` |
| Service | `/Library/LaunchDaemons/com.routewise.helper.plist` | `routewise.service` | Service `RouteWise` |
| Socket | `/var/run/routewise.sock` | `/run/routewise.sock` | `\\.\pipe\routewise` |
| Helper logs | `/var/log/routewise-YYYY-MM-DD.log` | `/var/log/routewise/` | `%ProgramData%\RouteWise\logs\` |
| App logs | `~/Library/Logs/RouteWise/` | `~/.local/state/RouteWise/logs/` | `%LOCALAPPDATA%\RouteWise\logs\` |
| Route journals | `/var/run/routewise/` | Same purpose, per platform | Same purpose, per platform |

Daily logs keep 14 days. On macOS `/var/log/routewise.log` holds only what launchd captures, which is mainly crash output.
**Settings** has buttons that open both log folders.

## What the database holds

Configuration, built-in VPN credentials, per-user app preferences, the access history and the activity log, in one SQLite file. It is
root-only. Do not edit it by hand.

## Backups and recovery

| File | Written | Purpose |
|---|---|---|
| `routewise.db.bak` | After every save | Configuration, credentials and preferences, never history |
| `routewise.db.v<N>.bak` | Before upgrading schema `N` | Rolling back to an older helper. Never rewritten |
| `routewise.db.corrupt-<timestamp>` | When damage is found at start | The damaged file, moved aside |

A damaged database is rebuilt from `.bak`, else from `config.yaml.migrated`, else from defaults. History and activity then start empty. A
newer schema, a locked database or an invalid configuration is never moved aside.

A `config.yaml` from an older version is imported on first start and renamed `config.yaml.migrated`. It is kept and no longer read.

## Crash journals

These record what must be undone after a crash, and the next start clears them:

| File | Records |
|---|---|
| `transition.json`, `transition-<interface>.json` | Each tunnel's activation |
| `ipv6-blocked.json` | IPv6 addresses blocked for listed names |
| `default-vpn-routes.json` | The default VPN's routes, server routes, exception routes and IPv6 block |
